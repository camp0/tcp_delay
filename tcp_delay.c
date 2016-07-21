/*
 *  tcp_delay - Delays TCP network connections.
 *
 *  Copyright (C) 2016 Luis Campo Giralte <luis.camp0.2009@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <linux/ctype.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#ifdef CONFIG_NET_NS
#include <net/net_namespace.h>
#endif
#include <net/ip.h>
#include <net/tcp.h>
#include <net/inet_hashtables.h>

#define TCP_DELAY_PROC    "tcp_delay"
#define TCP_DELAY_MAX_ARG 128 
#define MAX_KEY_HASH_SIZE 128

static int timeout = 180000;

module_param(timeout, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(timeout, "Timeout in secs for delay the TCP connection");

MODULE_AUTHOR("Luis Campo Giralte");
MODULE_LICENSE("GPL");

DEFINE_HASHTABLE(tcp_delay_hash_table,7);

struct tcp_delay_hash_node {
 	/* For hash table */
  	struct hlist_node hash_node;
	char key[MAX_KEY_HASH_SIZE];
	__be32 ipsrc;
	__be32 ipdst;
	uint16_t portsrc;
	uint16_t portdst;
	int sk_sndbuf;
	int32_t expires;
	struct timer_list timer;
};

struct proc_dir_entry *proc_file_entry;

void tcp_delay_timer_callback( unsigned long data )
{
	struct sock *sk = NULL;
	struct tcp_delay_hash_node *node = (struct tcp_delay_hash_node*)data;
	int ret;

        sk = inet_lookup(
#ifdef CONFIG_NET_NS
        	&init_net,
#endif
                &tcp_hashinfo,
                node->ipdst, htons(node->portdst),
                node->ipsrc, htons(node->portsrc),
                0);

	/* The connection still exists on the kernel */
	if (sk) {
        	lock_sock(sk);

        	sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
        	sk->sk_sndbuf = node->sk_sndbuf;
        	sk->sk_write_space(sk);

        	release_sock(sk);

        	printk(KERN_INFO "tcp_delay: timer expires on connection (%s)\n", node->key);

        	ret = del_timer( &node->timer );
        	if (ret) printk(KERN_INFO "tcp_delay: The timer is still in use for connection (%s)\n", node->key);

	} else {
		/* The connection dont exists on the kernel, long timeout or rst/fin */
        	printk(KERN_INFO "tcp_delay: timer expires but connection (%s) not found\n", node->key);
	}

	hash_del_rcu(&node->hash_node);
	kfree(node);
}

uint64_t flow_key_64(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
	return (((31 + src_ip) * 31 + dst_ip) * 31 + src_port) * 31 + dst_port;
}

int tcp_delay_process_connection(char *local_ip, char *remote_ip, uint16_t local_port,uint16_t remote_port,char *key_str)
{ 
	struct sock *sk = NULL;
        // struct hlist_node *temp_node = NULL;
        struct tcp_delay_hash_node *entry = NULL;
        uint32_t ipsrc = in_aton(local_ip);
        uint32_t ipdst = in_aton(remote_ip);
	int ret = 0;

	/* hash the 4 tuple */
        uint64_t hash = flow_key_64(ipsrc,local_port,ipdst,remote_port);

        /* Find if we have a timer setup for that connection */
        hash_for_each_possible_rcu (tcp_delay_hash_table,entry,hash_node,hash) {
                if (entry->ipsrc == ipsrc && entry->ipdst == ipdst && entry->portsrc == local_port && entry->portdst == remote_port) {
                        break;
                }
        }

	sk = inet_lookup(
#ifdef CONFIG_NET_NS
		&init_net, 
#endif
		&tcp_hashinfo,
		ipdst, htons(remote_port), 
		ipsrc, htons(local_port), 
		0);

	/* If the connnection dont exists return */
	if (sk == NULL) {
		printk(KERN_DEBUG "tcp_delay: connection (%s) not found(%d)(%d)\n", key_str,local_port,remote_port);
		return -1;
	}

        if (entry == NULL) {
                entry  = (struct tcp_delay_hash_node *)kmalloc(sizeof(struct tcp_delay_hash_node), GFP_KERNEL);
                if (!entry)
                        return -ENOMEM;

                entry->ipsrc = ipsrc;
                entry->ipdst = ipdst;
                entry->portsrc = local_port;
                entry->portdst = remote_port;
                memcpy(&entry->key,key_str,MAX_KEY_HASH_SIZE);

                printk(KERN_DEBUG "tcp_delay: adding new connection (%s)\n", key_str);
                hash_add_rcu(tcp_delay_hash_table, &entry->hash_node, hash);
        
		setup_timer( &entry->timer, tcp_delay_timer_callback, (unsigned long)entry );
	}

	lock_sock(sk);

	entry->sk_sndbuf = sk->sk_sndbuf;
	sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
	sk->sk_sndbuf = 0;
	sk->sk_write_space(sk);

	release_sock(sk);

	entry->expires = jiffies;

        ret = mod_timer( &entry->timer, jiffies + msecs_to_jiffies(timeout));
        if (ret) printk(KERN_DEBUG "tcp_delay: can not modify timer\n");
                
	printk(KERN_DEBUG "tcp_delay: connection (%s) timer setup\n", key_str);

	return 0;
}

/* This function expects a copy/paste of netstat output on the form
   "192.168.1.113:7777           192.158.1.115:15723"
*/
static int parse_user_input(char *buffer, int length ) 
{
	char local_ip[INET_ADDRSTRLEN];
	char remote_ip[INET_ADDRSTRLEN];
	char key_buffer[MAX_KEY_HASH_SIZE];
	char port_buffer[8];
	int local_port = 0;
	int remote_port = 0;
	int prev_idx = 0;
	int curr_idx = 0;
	int curr_len = 0;
	char *ptr = buffer;
	int ret;

	memset(&local_ip,0,INET_ADDRSTRLEN);
	memset(&remote_ip,0,INET_ADDRSTRLEN);
	memset(&port_buffer,0,8);
	
	for (curr_idx = prev_idx; curr_idx < length && ptr[curr_idx] != ':' ; curr_idx++) {}

	curr_len = curr_idx - prev_idx;
	if (curr_len > INET_ADDRSTRLEN) 
		goto parse_error;

	/* extract the local ip address */
	if (ptr[curr_idx] == ':') {
		memcpy(&local_ip,&ptr[prev_idx],curr_idx);
	} 

	prev_idx = curr_idx + 1;
	for (curr_idx = prev_idx; curr_idx < length && ptr[curr_idx] != ' ' ; curr_idx++) {}

	curr_len = curr_idx - prev_idx;
	if (curr_len > 7 ) 
		goto parse_error;

	/* extract the local port */
	if (ptr[curr_idx] == ' ') {
		memcpy(&port_buffer,&ptr[prev_idx],curr_len);
		ret = kstrtoint(port_buffer,10,&local_port);
		if (ret != 0) 
			goto parse_error;
	} 

	prev_idx = curr_idx + 1;
	for (curr_idx = prev_idx; curr_idx < length && ptr[curr_idx] != ':' ; curr_idx++) {
		if (ptr[curr_idx] == ' ') prev_idx++;
	}

        curr_len = curr_idx - prev_idx;
        if (curr_len > INET_ADDRSTRLEN)
                goto parse_error;

        /* extract the remote ip address */
        if (ptr[curr_idx] == ':') {
                memcpy(&remote_ip,&ptr[prev_idx],curr_len);
        }

	prev_idx = curr_idx + 1;
	for (curr_idx = prev_idx; curr_idx < length ; curr_idx++) {}

	curr_len = curr_idx - prev_idx;
	if (curr_len > 7 ) 
		goto parse_error;

	// Is the last item
	memcpy(&port_buffer,&ptr[prev_idx],curr_len);
	ret = kstrtoint(port_buffer,10,&remote_port);
	if (ret != 0) 
		goto parse_error;

	snprintf(key_buffer,MAX_KEY_HASH_SIZE,"%s:%d:%s:%d" ,local_ip,local_port,remote_ip,remote_port);

	return tcp_delay_process_connection(local_ip,remote_ip,local_port,remote_port,&key_buffer[0]);

parse_error:
	printk (KERN_ERR "tcp_delay: incorrect user input\n");
	return -1;
}

static ssize_t tcp_delay_write_proc(struct file *file, const char __user *buffer,
	size_t count, loff_t *p_off)
{
	ssize_t ret = -EFAULT;
	char   *kbuffer;

	if (!count || count > TCP_DELAY_MAX_ARG)
		return -EOVERFLOW;

	kbuffer = (char *)kmalloc(count, GFP_KERNEL);
	if (!kbuffer)
		return ret;

        if (!copy_from_user(kbuffer,buffer,count) && !parse_user_input(kbuffer,count)) 
	{
		ret = count;
	}	

	kfree(kbuffer);
	return ret;
}

static ssize_t tcp_delay_read_proc( struct file *filp, char __user *buff,
            size_t count, loff_t *off )
{
	ssize_t ret = 0;
	struct hlist_node *temp_node = NULL;
        struct tcp_delay_hash_node *entry = NULL;
	char outbuff[256];
	int counter;

        hash_for_each_safe (tcp_delay_hash_table, counter, temp_node, entry, hash_node) {
		int expires_on = timeout - (jiffies - entry->expires);
		snprintf(outbuff,256,"%s %d\n",&entry->key[0],expires_on);

		ret += simple_read_from_buffer(buff, count, off, outbuff, strlen(outbuff));
        }
    	return ret;
}


static struct file_operations tcp_delay_proc_ops = {
	.owner   = THIS_MODULE,
	.read = tcp_delay_read_proc,
	.write = tcp_delay_write_proc
};

static int __init tcp_delay_init(void)
{
	printk(KERN_INFO "TCPDelay v1.0 registered\n");

	proc_file_entry = proc_create(TCP_DELAY_PROC, 
		S_IWUSR | S_IWGRP,
#ifdef CONFIG_NET_NS
		init_net.proc_net,
#else
		NULL,
#endif
		&tcp_delay_proc_ops);

	if (proc_file_entry == NULL) {
		printk(KERN_ERR "tcp_delay: unable to register proc file\n");
   		return -ENOMEM;
	}
	return 0;
}

static void __exit tcp_delay_exit(void)
{
	int counter;
        struct tcp_delay_hash_node *entry;
	struct hlist_node *temp_node;

	printk(KERN_INFO "TCPDelay v1.0 unregistered\n");

	proc_remove (proc_file_entry);

	hash_for_each_safe (tcp_delay_hash_table, counter, temp_node, entry, hash_node) {
		hash_del(&entry->hash_node);
		kfree(entry);
		entry = NULL;
	}
}

module_init(tcp_delay_init);
module_exit(tcp_delay_exit);

