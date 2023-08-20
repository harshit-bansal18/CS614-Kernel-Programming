#include <crypter.h>
#include <string.h>
#include<stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define MAX_CHUNK_SIZE (16*1024)

unsigned long map_len = 0;

static inline int set_handle(DEV_HANDLE handle) {
    int fd;
    char buf[10];
    int count;
    fd =  open("/sys/kernel/cryptocard/live_handle", O_WRONLY);
    if (fd < 0) {
        printf("crypter: error: cannot open live_handle\n");
        return ERROR;
    }
    count = sprintf(buf, "%d", handle);
    if (write(fd, buf, count) < 0)
        goto wr_err;

    close(fd);
    return 0;

wr_err:
    close(fd);
    return ERROR;
}

/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
DEV_HANDLE create_handle()
{
  int fd;
  char buf[10];
  DEV_HANDLE handle;
  
  fd = open("/sys/kernel/cryptocard/handle", O_RDONLY);
  if (fd < 0){
    printf("crypter: error: cannot open handle file\n");
    return ERROR;
  }

  if(read(fd, buf, 10) < 0) {
    printf("crypter: error: read failed from handle\n");
    goto err;
  }

  handle = atoi(buf);
  if (buf < 0){
    printf("crypter: error: handle not integer\n");
    goto err;
  }

  close(fd);
  return handle;

err:
  close(fd);
  return ERROR;

}

/*Function template to close device handle.
Takes an already opened device handle as an arguments*/
void close_handle(DEV_HANDLE cdev)
{
  int fd, count;
  char buf[10];
  fd = open("/sys/kernel/cryptocard/handle", O_WRONLY);
  count = sprintf(buf, "%d", cdev);
  if(write(fd, buf, count) < 0)
    goto err;
  
err:
  close(fd);
}

int __encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped){
  int fd;
  char buf[length + 3];
  fd = open("/dev/crypto", O_RDWR);
  if (fd < 0) {
    printf("crypter: Error: cannot open encrypt\n");
    return ERROR;
  }
  if (set_handle(cdev) < 0)
    goto err;
  
  buf[0] = 'e';
  if(isMapped){
    buf[1] = 'm';
    if (write(fd, buf, length+2) < 0) {
      printf("crypter: Error: decrypt failed\n");
      goto err;
    }

    close(fd);
    return 0;
  }

  buf[1] = 'n';
  memcpy(buf+2, addr, length);

  if (write(fd, buf, length+2) < 0)
    goto err;

  if (read(fd, addr, length) < 0)
    goto err;
  
  close(fd);
  return 0;

err:
  close(fd);
  return ERROR;
}

/*Function template to encrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which encryption has to be performed
  length: size of data to be encrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  unsigned long num_chunks = length/MAX_CHUNK_SIZE;
  unsigned long rem = length%MAX_CHUNK_SIZE;
  int ret;
  if(rem) num_chunks += 1;
  for(unsigned long chunk = 0; chunk < num_chunks ; chunk++){
    unsigned long offset = chunk*MAX_CHUNK_SIZE;
    unsigned long len_msg = length - offset;
    if(len_msg > MAX_CHUNK_SIZE)
      len_msg = MAX_CHUNK_SIZE;
    
    ret = __encrypt(cdev, addr+offset, len_msg, isMapped);
    if (ret < 0)
      return ret;
  }
  return 0;
}


int __decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  int fd;
  char buf[length +3];
  fd = open("/dev/crypto", O_RDWR);
  if (fd < 0) {
    printf("crypter: Error: cannot open decrypt\n");
    return ERROR;
  }

  if (set_handle(cdev) < 0)
    goto err;
  
  buf[0] = 'd';

  if(isMapped){
    buf[1] = 'm';
    if (write(fd, buf, length+2) < 0) {
      printf("crypter: Error: decrypt failed\n");
      goto err;
    }

    close(fd);
    return 0;
  }

  buf[1] = 'n';

  memcpy(buf+2, addr, length);
  if (write(fd, buf, length+2) < 0) {
    printf("crypter: Error: decrypt failed\n");
    goto err;
  }

  if (read(fd, addr, length) < 0) {
    printf("crypter: error: read failed\n");
    goto err;
  }
  close(fd);
  return 0;

err:
  close(fd);
  return ERROR;
}

/*Function template to decrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which decryption has to be performed
  length: size of data to be decrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  unsigned long num_chunks = length/MAX_CHUNK_SIZE;
  unsigned long rem = length%MAX_CHUNK_SIZE;
  int ret;
  if(rem) num_chunks += 1;

  for(unsigned long chunk = 0; chunk < num_chunks ; chunk++){
    unsigned long offset = chunk*MAX_CHUNK_SIZE;
    unsigned long len_msg = length - offset;
    if(len_msg > MAX_CHUNK_SIZE)
      len_msg = MAX_CHUNK_SIZE;
    
    ret = __decrypt(cdev, addr+offset, len_msg, isMapped);
    // printf("iter: ")
    if (ret < 0)
      return ret;
  }
  return 0;
}

/*Function template to set the key pair.
Takes three arguments
  cdev: opened device handle
  a: value of key component a
  b: value of key component b
Return 0 in case of key is set successfully*/
int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b)
{
  int fd;
  char keys[12] = {a, b};
  fd = open("/sys/kernel/cryptocard/keys", O_WRONLY);
  if (fd < 0) {
    printf("crypter: Error: cannot open keys\n");
    return -1;
  }
  
  sprintf(keys+2, "%d", cdev);
  if (write(fd, keys, 12) < 0) {
    printf("crypter: Error: cannot write to keys\n");
    goto err;
  }

  close(fd);
  return 0;

err:
  close(fd);
  return ERROR;
}

/*Function template to set configuration of the device to operate.
Takes three arguments
  cdev: opened device handle
  type: type of configuration, i.e. set/unset DMA operation, interrupt
  value: SET/UNSET to enable or disable configuration as described in type
Return 0 in case of key is set successfully*/
int set_config(DEV_HANDLE cdev, config_t type, uint8_t value)
{
  int _config;
  int size;
  char buf[4] = {'\0'};
  
  int fd = open("/sys/kernel/cryptocard/config", O_WRONLY);
  if (fd < 0)
    return ERROR;
  
  if (set_handle(cdev) < 0)
    goto err;
  
  if(type == INTERRUPT)
    _config = 1 & value;
  
  else if(type == DMA)
    _config = 2 | value;

  printf("crypter: value of config: %d\n", _config);
  
  size = sprintf(buf, "%d", _config);
  if(write(fd, buf, size) < 0){
    printf("crypter: failed to write to config\n");
    goto err;
  }

  close(fd);
  return 0;

err:
  close(fd);
  return ERROR;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
  char buf[22];

  if(size > 1024*1024){
    printf("Only 1 MB region mapping allowed\n");
    return NULL;
  }

  size += 0xa8;

  void* addr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);
  
  if(addr == NULL) {
    printf("Failed to map region to usersapce\n");
    return NULL;
  }

  map_len = size;
  
  int fd = open("/sys/kernel/cryptocard/map", O_WRONLY);

  if(fd < 0) {
    printf("Failed to open config  map file for the process to map the region\n");
    return NULL;
  }
  
  int count = sprintf(buf, "%ld", (unsigned long)addr);

  if(write(fd, buf, count) < 0){
    printf("Failed to map region to usersapce\n");
    return NULL;
  }

  close(fd);

  addr += 0xa8;
  return addr;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{
  munmap(addr, map_len);
  map_len = 0;
}
