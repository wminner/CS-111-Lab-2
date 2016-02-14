#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>  /* printk() */
#include <linux/errno.h>   /* error codes */
#include <linux/types.h>   /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/file.h>
#include <linux/list.h>	   /* linked list for pids */

#include "spinlock.h"
#include "osprd.h"

/* The size of an OSPRD sector. */
#define SECTOR_SIZE	512

/* This flag is added to an OSPRD file's f_flags to indicate that the file
 * is locked. */
#define F_OSPRD_LOCKED	0x80000

/* eprintk() prints messages to the console.
 * (If working on a real Linux machine, change KERN_NOTICE to KERN_ALERT or
 * KERN_EMERG so that you are sure to see the messages.  By default, the
 * kernel does not print all messages to the console.  Levels like KERN_ALERT
 * and KERN_EMERG will make sure that you will see messages.) */
#define eprintk(format, ...) printk(KERN_NOTICE format, ## __VA_ARGS__)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CS 111 RAM Disk");
// EXERCISE (DONE): Pass your names into the kernel as the module's authors.
MODULE_AUTHOR("Christie Mathews & Wesley Minner");

#define OSPRD_MAJOR	222

/* This module parameter controls how big the disk will be.
 * You can specify module parameters when you load the module,
 * as an argument to insmod: "insmod osprd.ko nsectors=4096" */
static int nsectors = 32;
module_param(nsectors, int, 0);

/* Linked list of tickets */
typedef struct ticket_list {
	unsigned ticket_num;
	struct list_head list;
} ticket_list_t;

/* Linked list of pids */
typedef struct pid_list {
	pid_t pid_num;
	struct list_head list;
} pid_list_t;

/* The internal representation of our device. */
typedef struct osprd_info {
	uint8_t *data;                  // The data array. Its size is
	                                // (nsectors * SECTOR_SIZE) bytes.

	osp_spinlock_t mutex;           // Mutex for synchronizing access to
					// this block device

	unsigned ticket_head;		// Currently running ticket for
					// the device lock

	unsigned ticket_tail;		// Next available ticket for
					// the device lock

	ticket_list_t invalid_tickets;	// Linked list to store invalid tickets

	wait_queue_head_t blockq;       // Wait queue for tasks blocked on
					// the device lock

	/* HINT: You may want to add additional fields to help
	         in detecting deadlock. */

	// Lists to store processes holding locks
	pid_list_t read_lock_pids;		// Linked list of pids currently reading
	pid_t write_lock_pids;				// Only need a list of one for pids currently writing

	// The following elements are used internally; you don't need
	// to understand them.
	struct request_queue *queue;    // The device request queue.
	spinlock_t qlock;		// Used internally for mutual
	                                //   exclusion in the 'queue'.
	struct gendisk *gd;             // The generic disk.
} osprd_info_t;

#define NOSPRD 4
static osprd_info_t osprds[NOSPRD];


// Declare useful helper functions
unsigned skip_invalid_tickets(unsigned next_ticket, ticket_list_t *invalid_tickets);
int add_to_ticket_list(unsigned new_ticket, ticket_list_t *ticket_list);
int add_to_pid_list(pid_t new_pid, pid_list_t *pid_list);
int remove_from_pid_list(pid_t rm_pid, pid_list_t *pid_list);

/*
 * file2osprd(filp)
 *   Given an open file, check whether that file corresponds to an OSP ramdisk.
 *   If so, return a pointer to the ramdisk's osprd_info_t.
 *   If not, return NULL.
 */
static osprd_info_t *file2osprd(struct file *filp);

/*
 * for_each_open_file(task, callback, user_data)
 *   Given a task, call the function 'callback' once for each of 'task's open
 *   files.  'callback' is called as 'callback(filp, user_data)'; 'filp' is
 *   the open file, and 'user_data' is copied from for_each_open_file's third
 *   argument.
 */
static void for_each_open_file(struct task_struct *task,
			       void (*callback)(struct file *filp,
						osprd_info_t *user_data),
			       osprd_info_t *user_data);


/*
 * osprd_process_request(d, req)
 *   Called when the user reads or writes a sector.
 *   Should perform the read or write, as appropriate.
 */
static void osprd_process_request(osprd_info_t *d, struct request *req)
{
	unsigned req_type;		// Request type: READ or WRITE
	uint8_t *data_offset;	// Pointer to data we are working with (in Ramdisk)
	size_t bytes_to_rw;		// Number of bytes to read/write

	if (!blk_fs_request(req)) {
		end_request(req, 0);
		return;
	}

	// EXERCISE (DONE): Perform the read or write request by copying data between
	// our data array and the request's buffer.
	// Hint: The 'struct request' argument tells you what kind of request
	// this is, and which sectors are being read or written.
	// Read about 'struct request' in <linux/blkdev.h>.
	// Consider the 'req->sector', 'req->current_nr_sectors', and
	// 'req->buffer' members, and the rq_data_dir() function.

	// Memory Offset from char* data (sector address + address of data within sector)
	data_offset = (req->sector)*SECTOR_SIZE + d->data;
 	// Number of Bytes to Read/Write
	bytes_to_rw = (req->current_nr_sectors)*SECTOR_SIZE;
	// Get request type
	req_type = rq_data_dir(req);

	// PERFORM READ
	if ( req_type == READ ) {
		memcpy( (void*) req->buffer, (void*) data_offset, bytes_to_rw );
	} 
	// PERFORM WRITE
	if ( req_type == WRITE ) {
		memcpy( (void*) data_offset, (void*) req->buffer, bytes_to_rw );
	}
	//eprintk("Should process request...\n");

	end_request(req, 1);
}


// This function is called when a /dev/osprdX file is opened.
// You aren't likely to need to change this.
static int osprd_open(struct inode *inode, struct file *filp)
{
	// Always set the O_SYNC flag. That way, we will get writes immediately
	// instead of waiting for them to get through write-back caches.
	filp->f_flags |= O_SYNC;
	return 0;
}


// This function is called when a /dev/osprdX file is finally closed.
// (If the file descriptor was dup2ed, this function is called only when the
// last copy is closed.)
static int osprd_close_last(struct inode *inode, struct file *filp)
{
	if (filp) {
		osprd_info_t *d = file2osprd(filp);
		int filp_writable = filp->f_mode & FMODE_WRITE;

		// EXERCISE: If the user closes a ramdisk file that holds
		// a lock, release the lock.  Also wake up blocked processes
		// as appropriate.

		if (filp_writable) {	// If writer...
			
			// TODO deadlock detection

			osp_spin_lock(&d->mutex);
			// If write lock was set and pid matched current pid...
			if ( d->write_lock_pids == current->pid ) {
				d->write_lock_pids = 0;		// Remove pid from writers list
				filp->f_flags ^= F_OSPRD_LOCKED;	// Clear LOCKED flag
				wake_up_all(&d->blockq);
			}
			osp_spin_unlock(&d->mutex);

		} else {	// If reader...
			
			// TODO deadlock detection

			osp_spin_lock(&d->mutex);
			// If read lock was set and pid matched one of the read lock pids...
			// Look through read lock list for current pid and remove it if found
			if ( remove_from_pid_list(current->pid, &d->read_lock_pids) ) {
				filp->f_flags ^= F_OSPRD_LOCKED;
				wake_up_all(&d->blockq);
			}
			osp_spin_unlock(&d->mutex);
		}
	}
	return 0;
}


/*
 * osprd_lock
 */

/*
 * osprd_ioctl(inode, filp, cmd, arg)
 *   Called to perform an ioctl on the named file.
 */
int osprd_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	unsigned local_ticket;
	osprd_info_t *d = file2osprd(filp);	// device info
	int r = 0;			// return value: initially 0

	// is file open for writing?
	int filp_writable = (filp->f_mode & FMODE_WRITE) != 0;

	// Set 'r' to the ioctl's return value: 0 on success, negative on error

	if (cmd == OSPRDIOCACQUIRE) {

		// EXERCISE: Lock the ramdisk.
		//
		// If *filp is open for writing (filp_writable), then attempt
		// to write-lock the ramdisk; otherwise attempt to read-lock
		// the ramdisk.
		//
                // This lock request must block using 'd->blockq' until:
		// 1) no other process holds a write lock;
		// 2) either the request is for a read lock, or no other process
		//    holds a read lock; and
		// 3) lock requests should be serviced in order, so no process
		//    that blocked earlier is still blocked waiting for the
		//    lock.
		//
		// If a process acquires a lock, mark this fact by setting
		// 'filp->f_flags |= F_OSPRD_LOCKED'.  You also need to
		// keep track of how many read and write locks are held:
		// change the 'osprd_info_t' structure to do this.
		//
		// Also wake up processes waiting on 'd->blockq' as needed.
		//
		// If the lock request would cause a deadlock, return -EDEADLK.
		// If the lock request blocks and is awoken by a signal, then
		// return -ERESTARTSYS.
		// Otherwise, if we can grant the lock request, return 0.

		// 'd->ticket_head' and 'd->ticket_tail' should help you
		// service lock requests in order.  These implement a ticket
		// order: 'ticket_tail' is the next ticket, and 'ticket_head'
		// is the ticket currently being served.  You should set a local
		// variable to 'd->ticket_head' and increment 'd->ticket_head'.
		// Then, block at least until 'd->ticket_tail == local_ticket'.
		// (Some of these operations are in a critical section and must
		// be protected by a spinlock; which ones?)

		// For our implementation, define...
		// 	 ticket_head as front of the line (next to be served)
		// 	 ticket_tail as back of the line (last to be served)
		osp_spin_lock(&d->mutex);
		local_ticket = d->ticket_tail;	// Give process end of the line ticket
		d->ticket_tail++;				// Extend end of line, prepping for next process
		osp_spin_unlock(&d->mutex);

		if (filp_writable) {	// Write-lock

			// Deadlock detection (don't allow writer to lock twice)
			if (current->pid == d->write_lock_pids)
				return -EDEADLK;

			// Don't wait condition: if this process is being served and there are no writing or reading pids; otherwise wait
			if ( wait_event_interruptible(d->blockq, d->ticket_head == local_ticket && d->write_lock_pids == 0 && list_empty(&d->read_lock_pids.list)) ) {
				// In here means we got a signal and need to handle now invalid ticket
				osp_spin_lock(&d->mutex);

				if ( d->ticket_head == local_ticket ) {		// If this process (dead) was next in line...
					// Don't need to add to invalid ticket list because implicit in next function call
					// Get next ticket to be served, skipping any invalid tickets
					d->ticket_head = skip_invalid_tickets(d->ticket_head+1, &d->invalid_tickets);
					// Wake up waiting processes
					wake_up_all(&d->blockq);
				} else {	// Else if this process (dead) not next in line...
					// Add current ticket to invalid list
					if ( add_to_ticket_list(local_ticket, &d->invalid_tickets) < 0 ) {
						eprintk("Error: could not allocate memory.\n");
						return -EINVAL;
					}
				}

				osp_spin_unlock(&d->mutex);
				r = -ERESTARTSYS;
			} else {	// Don't wait condition was true; grant write-lock
				filp->f_flags |= F_OSPRD_LOCKED;
				
				// Set writing pid to current pid (list of one)
				osp_spin_lock(&d->mutex);
				d->write_lock_pids = current->pid;

				// Serve next ticket
				d->ticket_head = skip_invalid_tickets(d->ticket_head+1, &d->invalid_tickets);
				wake_up_all(&d->blockq);

				osp_spin_unlock(&d->mutex);
			}
		} else {	// Read-lock

			// TODO deadlock detection (none?)

			// Don't wait condition: if this process is being served and there are no writing pids; otherwise wait
			if ( wait_event_interruptible(d->blockq, d->ticket_head == local_ticket && d->write_lock_pids == 0) ) {
				// In here means we got a signal and need to handle now invalid ticket
				osp_spin_lock(&d->mutex);

				if ( d->ticket_head == local_ticket ) {		// If this process (dead) was next in line...
					// Don't need to add to invalid ticket list because implicit in next function call
					// Get next ticket to be served, skipping any invalid tickets
					d->ticket_head = skip_invalid_tickets(d->ticket_head+1, &d->invalid_tickets);
					// Wake up waiting processes
					wake_up_all(&d->blockq);
				} else {	// Else if this process (dead) not next in line...
					// Add current ticket to invalid list
					if ( add_to_ticket_list(local_ticket, &d->invalid_tickets) < 0 ) {
						eprintk("Error: could not allocate memory.\n");
						return -EINVAL;
					}
				}

				osp_spin_unlock(&d->mutex);
				r = -ERESTARTSYS;
			} else {	// Don't wait condition was true; grand read-lock
				filp->f_flags |= F_OSPRD_LOCKED;

				// Add pid to reading pid list
				osp_spin_lock(&d->mutex);
				if ( add_to_pid_list(current->pid, &d->read_lock_pids) < 0 ) {
					eprintk("Error: could not allocate memory.\n");
					return -EINVAL;
				}

				// Serve next ticket
				d->ticket_head = skip_invalid_tickets(d->ticket_head+1, &d->invalid_tickets);
				wake_up_all(&d->blockq);

				osp_spin_unlock(&d->mutex);
			}
		}

		// eprintk("Attempting to acquire\n");
		// r = -ENOTTY;

	} else if (cmd == OSPRDIOCTRYACQUIRE) {

		// EXERCISE: ATTEMPT to lock the ramdisk.
		//
		// This is just like OSPRDIOCACQUIRE, except it should never
		// block.  If OSPRDIOCACQUIRE would block or return deadlock,
		// OSPRDIOCTRYACQUIRE should return -EBUSY.
		// Otherwise, if we can grant the lock request, return 0.

		// Your code here (instead of the next two lines).
		eprintk("Attempting to try acquire\n");
		r = -ENOTTY;

	} else if (cmd == OSPRDIOCRELEASE) {

		// EXERCISE: Unlock the ramdisk.
		//
		// If the file hasn't locked the ramdisk, return -EINVAL.
		// Otherwise, clear the lock from filp->f_flags, wake up
		// the wait queue, perform any additional accounting steps
		// you need, and return 0.

		if (filp_writable) {	// If writer...
			
			// TODO deadlock detection

			osp_spin_lock(&d->mutex);
			// If write lock was set and pid matched current pid...
			if ( d->write_lock_pids == current->pid ) {
				d->write_lock_pids = 0;		// Remove pid from writers list
				filp->f_flags ^= F_OSPRD_LOCKED;	// Clear LOCKED flag
				wake_up_all(&d->blockq);
			} else {
				eprintk("Error: Unlocking ramdisk; this file did not lock the ramdisk!\n");
				r = -EINVAL;
			}
			osp_spin_unlock(&d->mutex);

		} else {	// If reader...
			
			// TODO deadlock detection

			osp_spin_lock(&d->mutex);
			// If read lock was set and pid matched one of the read lock pids...
			// Look through read lock list for current pid and remove it if found
			if ( remove_from_pid_list(current->pid, &d->read_lock_pids) ) {
				filp->f_flags ^= F_OSPRD_LOCKED;
				wake_up_all(&d->blockq);
			} else {
				eprintk("Error: Unlocking ramdisk; this file did not lock the ramdisk!\n");
				r = -EINVAL;
			}
			osp_spin_unlock(&d->mutex);
		}
		
		// Your code here (instead of the next line).
		// r = -ENOTTY;

	} else
		r = -ENOTTY; /* unknown command */
	return r;
}

/* 
 * skip_invalid_tickets( next_ticket, invalid_ticket_list)
 *   Find the next valid ticket by skipping invalid tickets.
 *   Must search from start of invalid ticket list each time in case processes die
 *   out of order.  Returns the next valid ticket;
 */
unsigned skip_invalid_tickets(unsigned next_ticket, ticket_list_t *invalid_tickets) {
	struct list_head *ptr;
	ticket_list_t *entry;
	unsigned return_ticket = next_ticket;

	// For each ticket in linked list
	list_for_each(ptr, &invalid_tickets->list) {
		
		// Get struct that contains the current list
		entry = list_entry(ptr, ticket_list_t, list);
		
		// If next_ticket matches any invalid tickets...
		if ( entry->ticket_num == next_ticket ) {
			// Recurse with incremented next_ticket
			return_ticket = skip_invalid_tickets(next_ticket+1, invalid_tickets);
			break;
		}
	}
	return return_ticket;
}

int add_to_ticket_list(unsigned new_ticket, ticket_list_t *ticket_list) {
	ticket_list_t *new;

	// Allocate memory for new ticket_list_t
	new = (ticket_list_t*) kmalloc(sizeof(ticket_list_t), GFP_ATOMIC);
	
	if (new) {
		// Save desired ticket number
		new->ticket_num = new_ticket;
		
		// Add to tail of ticket_list
		list_add_tail(&new->list, &ticket_list->list);
		return 0;
	} else
		return -1;
}

int add_to_pid_list(pid_t new_pid, pid_list_t *pid_list) {
	pid_list_t *new;

	// Allocate memory for new pid_list_t
	new = (pid_list_t*) kmalloc(sizeof(pid_list_t), GFP_ATOMIC);
	
	if (new) {
		// Save desired pid number
		new->pid_num = new_pid;
		
		// Add to tail of pid_list
		list_add_tail(&new->list, &pid_list->list);
		return 0;
	} else
		return -1;
}

int remove_from_pid_list(pid_t rm_pid, pid_list_t *pid_list) {
	struct list_head *ptr;
	pid_list_t *entry;

	// List empty
	if ( list_empty(&pid_list->list) )
		return 0;

	// For each pid in linked list
	list_for_each(ptr, &pid_list->list) {
		entry = list_entry(ptr, pid_list_t, list);
		
		// If rm_pid matches any pid in list
		if ( entry->pid_num == rm_pid ) {
			// Remove it from list, free memory, and return 1
			list_del(&entry->list);
			kfree((void*) entry);
			return 1;
		}
	}		
	// rm_pid not found in list
	return 0;
}


// Initialize internal fields for an osprd_info_t.

static void osprd_setup(osprd_info_t *d)
{
	/* Initialize the wait queue. */
	init_waitqueue_head(&d->blockq);
	osp_spin_lock_init(&d->mutex);
	d->ticket_head = d->ticket_tail = 0;
	/* Add code here if you add fields to osprd_info_t. */
	d->write_lock_pids = 0;
	INIT_LIST_HEAD(&d->read_lock_pids.list);
	d->read_lock_pids.pid_num = 0;
	INIT_LIST_HEAD(&d->invalid_tickets.list);
	d->invalid_tickets.ticket_num = -1;
}


/*****************************************************************************/
/*         THERE IS NO NEED TO UNDERSTAND ANY CODE BELOW THIS LINE!          */
/*                                                                           */
/*****************************************************************************/

// Process a list of requests for a osprd_info_t.
// Calls osprd_process_request for each element of the queue.

static void osprd_process_request_queue(request_queue_t *q)
{
	osprd_info_t *d = (osprd_info_t *) q->queuedata;
	struct request *req;

	while ((req = elv_next_request(q)) != NULL)
		osprd_process_request(d, req);
}


// Some particularly horrible stuff to get around some Linux issues:
// the Linux block device interface doesn't let a block device find out
// which file has been closed.  We need this information.

static struct file_operations osprd_blk_fops;
static int (*blkdev_release)(struct inode *, struct file *);

static int _osprd_release(struct inode *inode, struct file *filp)
{
	if (file2osprd(filp))
		osprd_close_last(inode, filp);
	return (*blkdev_release)(inode, filp);
}

static int _osprd_open(struct inode *inode, struct file *filp)
{
	if (!osprd_blk_fops.open) {
		memcpy(&osprd_blk_fops, filp->f_op, sizeof(osprd_blk_fops));
		blkdev_release = osprd_blk_fops.release;
		osprd_blk_fops.release = _osprd_release;
	}
	filp->f_op = &osprd_blk_fops;
	return osprd_open(inode, filp);
}


// The device operations structure.

static struct block_device_operations osprd_ops = {
	.owner = THIS_MODULE,
	.open = _osprd_open,
	// .release = osprd_release, // we must call our own release
	.ioctl = osprd_ioctl
};


// Given an open file, check whether that file corresponds to an OSP ramdisk.
// If so, return a pointer to the ramdisk's osprd_info_t.
// If not, return NULL.

static osprd_info_t *file2osprd(struct file *filp)
{
	if (filp) {
		struct inode *ino = filp->f_dentry->d_inode;
		if (ino->i_bdev
		    && ino->i_bdev->bd_disk
		    && ino->i_bdev->bd_disk->major == OSPRD_MAJOR
		    && ino->i_bdev->bd_disk->fops == &osprd_ops)
			return (osprd_info_t *) ino->i_bdev->bd_disk->private_data;
	}
	return NULL;
}


// Call the function 'callback' with data 'user_data' for each of 'task's
// open files.

static void for_each_open_file(struct task_struct *task,
		  void (*callback)(struct file *filp, osprd_info_t *user_data),
		  osprd_info_t *user_data)
{
	int fd;
	task_lock(task);
	spin_lock(&task->files->file_lock);
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 13)
		struct files_struct *f = task->files;
#else
		struct fdtable *f = task->files->fdt;
#endif
		for (fd = 0; fd < f->max_fds; fd++)
			if (f->fd[fd])
				(*callback)(f->fd[fd], user_data);
	}
	spin_unlock(&task->files->file_lock);
	task_unlock(task);
}


// Destroy a osprd_info_t.

static void cleanup_device(osprd_info_t *d)
{
	wake_up_all(&d->blockq);
	if (d->gd) {
		del_gendisk(d->gd);
		put_disk(d->gd);
	}
	if (d->queue)
		blk_cleanup_queue(d->queue);
	if (d->data)
		vfree(d->data);
}


// Initialize a osprd_info_t.

static int setup_device(osprd_info_t *d, int which)
{
	memset(d, 0, sizeof(osprd_info_t));

	/* Get memory to store the actual block data. */
	if (!(d->data = vmalloc(nsectors * SECTOR_SIZE)))
		return -1;
	memset(d->data, 0, nsectors * SECTOR_SIZE);

	/* Set up the I/O queue. */
	spin_lock_init(&d->qlock);
	if (!(d->queue = blk_init_queue(osprd_process_request_queue, &d->qlock)))
		return -1;
	blk_queue_hardsect_size(d->queue, SECTOR_SIZE);
	d->queue->queuedata = d;

	/* The gendisk structure. */
	if (!(d->gd = alloc_disk(1)))
		return -1;
	d->gd->major = OSPRD_MAJOR;
	d->gd->first_minor = which;
	d->gd->fops = &osprd_ops;
	d->gd->queue = d->queue;
	d->gd->private_data = d;
	snprintf(d->gd->disk_name, 32, "osprd%c", which + 'a');
	set_capacity(d->gd, nsectors);
	add_disk(d->gd);

	/* Call the setup function. */
	osprd_setup(d);

	return 0;
}

static void osprd_exit(void);


// The kernel calls this function when the module is loaded.
// It initializes the 4 osprd block devices.

static int __init osprd_init(void)
{
	int i, r;

	// shut up the compiler
	(void) for_each_open_file;
#ifndef osp_spin_lock
	(void) osp_spin_lock;
	(void) osp_spin_unlock;
#endif

	/* Register the block device name. */
	if (register_blkdev(OSPRD_MAJOR, "osprd") < 0) {
		printk(KERN_WARNING "osprd: unable to get major number\n");
		return -EBUSY;
	}

	/* Initialize the device structures. */
	for (i = r = 0; i < NOSPRD; i++)
		if (setup_device(&osprds[i], i) < 0)
			r = -EINVAL;

	if (r < 0) {
		printk(KERN_EMERG "osprd: can't set up device structures\n");
		osprd_exit();
		return -EBUSY;
	} else
		return 0;
}


// The kernel calls this function to unload the osprd module.
// It destroys the osprd devices.

static void osprd_exit(void)
{
	int i;
	for (i = 0; i < NOSPRD; i++)
		cleanup_device(&osprds[i]);
	unregister_blkdev(OSPRD_MAJOR, "osprd");
}


// Tell Linux to call those functions at init and exit time.
module_init(osprd_init);
module_exit(osprd_exit);
