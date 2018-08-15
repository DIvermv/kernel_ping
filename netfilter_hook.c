/* хедеры */
#include  <linux/kernel.h>
#include  <linux/module.h>
#include <linux/init.h>

//#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include  <linux/netfilter_ipv4.h>
#include  <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/ktime.h>


static struct nf_hook_ops nfho;
static struct socket *clientsocket=NULL;
static unsigned long bloked_port;

static    ktime_t kt;
static unsigned int hook_func(void* priv, struct sk_buff *skb, const struct nf_hook_state* state)
{
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct icmphdr *icmp_header;
    unsigned int type, code,source_ip;
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    kt=ktime_set(ts.tv_sec,ts.tv_nsec)-kt;
     source_ip=ip_header->saddr;
    if (ip_header->protocol == 1) //ICMP protocol
    {
        icmp_header= (struct icmphdr *)((__u32 *)ip_header+ ip_header->ihl);
        type = ntohs(icmp_header->type);
        code = ntohs(icmp_header->code);


//	clock_gettime(clk_id, &ts);
//	cur_time=var->base->get_time();      // текущее время в типе ktime_t
        if(type==ICMP_ECHOREPLY && code==0)
        {
            printk("IP Source: %i ping at %lli mks \n",source_ip,kt/1000);
            //printk("IP Source: %i ping at %lds %lins \n",source_ip,ts.tv_sec,ts.tv_nsec);
	    return NF_DROP;
        }
    }
    return NF_ACCEPT; //accept the packet
}


static ssize_t f_proc_write(struct file *file, const char __user *ubuf,
				  size_t len, loff_t *offp)
{
	char tmpbuf[80];
    struct timespec64 ts;
    ktime_get_real_ts64(&ts);
    kt=ktime_set(ts.tv_sec,ts.tv_nsec);
	char buf[64];
	int i=0;
	struct msghdr msg;
	struct sockaddr_in to;
	struct iovec iov;
//	struct kvec iov;
	struct iov_iter iov_it;
	#ifndef KSOCKET_ADDR_SAFE
	 mm_segment_t old_fs;
        #endif
	  memset(&iov_it,0,sizeof(iov_it));
	if (len == 0)
		return 0;
        for ( i = 0; i < len; i++)
           get_user(tmpbuf[i],ubuf + i);

         tmpbuf[i] = '\0';    /* Обычная строка, завершающаяся символом \0 */
	//kstrtoul(tmpbuf,10,&bloked_port);
         if(sock_create(AF_INET,SOCK_RAW,IPPROTO_ICMP,&clientsocket)<0)
        // if(sock_create(AF_INET,SOCK_DGRAM,IPPROTO_UDP,&clientsocket)<0)
	 	printk("Ошибка создания сокета\n");
	 memset(&to,0, sizeof(to));
 	 to.sin_family = AF_INET;
 	 to.sin_addr.s_addr = in_aton( tmpbuf );// tmpbuf  
	 to.sin_port = htons(7777);
	memset(&msg,0,sizeof(msg));
	  msg.msg_name = &to;
	  msg.msg_namelen = sizeof(to);
        
	memset(buf,0,sizeof(buf));  
	buf[0]=0x08;
        buf[1]=0x00;
        buf[2]=0xf2;
        buf[3]=0x4b;	
	memcpy(&buf[5], "hallo from kernel space",sizeof( "hallo from kernel space") );
	  iov.iov_base =(void *) buf;
	  iov.iov_len  = sizeof( buf);
	  iov_iter_init(&iov_it,READ,&iov,1,sizeof(buf));
	  msg.msg_iter    = iov_it;
	  msg.msg_control = NULL;
	  msg.msg_controllen = 0;
	  msg.msg_flags=0;
	#ifndef KSOCKET_ADDR_SAFE
	 old_fs = get_fs();
	 set_fs(KERNEL_DS);
        #endif
	    len = sock_sendmsg(clientsocket, &msg);
        #ifndef KSOCKET_ADDR_SAFE
	 set_fs(old_fs);
        #endif
            //printk("IP ping: %s ping at %lld \n",tmpbuf,kt);
//	 printk("Заблокирован TCP порт %li\n",bloked_port);

       return i;
}
static const struct file_operations file_fops = {
    // .open = tasks_proc_open,
    // .read = seq_read,
    // .llseek = seq_lseek,
    // .release = single_release,
    // .write = seq_write
     .write = f_proc_write
    };
/* стандартная функция инициализации */
static int __init init_hook(void)
{
	int retval;
	bloked_port=-1;
    nfho.hook = hook_func;
    nfho.hooknum  = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    retval = nf_register_net_hook(&init_net, &nfho);
    printk("nf_register_net_hook returned %d\n", retval);

    if(proc_create("Tcp_block_port",0,NULL,&file_fops))
    	printk("Tcp_block_port created \n");
    return retval;
}
 
/* стандартная функция удаления модуля */
static void __exit cleanup_hook(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk("Unregistered the net hook.\n");
    remove_proc_entry("Tcp_block_port",NULL);
}

  MODULE_LICENSE("GPL"); 
  module_init(init_hook);
  module_exit(cleanup_hook); 
