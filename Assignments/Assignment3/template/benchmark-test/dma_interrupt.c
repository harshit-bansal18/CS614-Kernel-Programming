#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>

void* map_file(int * file_desc, int *file_size)
{
  struct stat file_stats;
  int fd = open("/dev/shm/in_memory.txt", O_RDWR);
  if(fd < 0)
  {
     printf("Error Occured while opening the file \n");
     exit(0);
  }

  fstat(fd, &file_stats);

  void * buff_address;
  buff_address = mmap(NULL, file_stats.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_POPULATE, fd, 0);
  if(buff_address <= 0)
  {
    printf("Error while mapping the file\n");
    exit(0);
  }

  *file_desc = fd;
  *file_size = file_stats.st_size;

  return buff_address;

}

int main()
{

  int file_desc = 0, file_size = 0;
  void *buffer =  map_file(&file_desc, &file_size);

  DEV_HANDLE cdev;
  KEY_COMP a=30, b=17;
  struct timeval start_time, end_time;
  cdev = create_handle();

  if(cdev == ERROR)
  {
    printf("Unable to create handle for device\n");
    exit(0);
  }

  // Setting the DMA
  set_config(cdev, DMA, SET);

  // Setting the Interrupt
  set_config(cdev, INTERRUPT, SET);

  if(set_key(cdev, a, b) == ERROR){
    printf("Unable to set key\n");
    exit(0);
  }

  unsigned int chunk_size = 4096;
  unsigned int number_of_chunk = (file_size / chunk_size);
  gettimeofday(&start_time, NULL);
  for(unsigned int chunk = 0; chunk < number_of_chunk ; chunk++)
  {
      unsigned int offset = (chunk*chunk_size);
      void *buffer_address = buffer + offset;

      encrypt(cdev, buffer_address, chunk_size, 0);
      decrypt(cdev, buffer_address, chunk_size, 0);
  }
  gettimeofday(&end_time, NULL);
  printf("%ld microseconds\n", (end_time.tv_sec*1000000 + end_time.tv_usec) - (start_time.tv_sec*1000000+start_time.tv_usec));
  close_handle(cdev);
  munmap(buffer, file_size);
  close(file_desc);

  return 0;
}