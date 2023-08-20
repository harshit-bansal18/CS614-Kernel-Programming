#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>
#include <pthread.h>

#define NUM_THREADS 1

#define MAP_SIZE 2048


void *run(void *arg) {
  int tid = *(int*)arg;
  printf("starting thread %d...\n", tid);
  DEV_HANDLE cdev;

  char *op_text;
  op_text = (char*) malloc((MAP_SIZE+1) * sizeof(char));
  
  KEY_COMP a=16 * (tid%16), b=17;
  printf("[Tid: %d] Keys a: %d, Key b: %d\n", tid, a, b);
 
  printf("[%d] calling create handle\n", tid);
  for(int i=0; i<MAP_SIZE; i++)
    op_text[i] = 'a' + (i%26);
  
  op_text[MAP_SIZE] = '\0';
  // printf("Original Text: %s\n\n\n", op_text);
  // int size = sprintf(op_text, "Khush it 27");
  
  cdev = create_handle();

  if(cdev == ERROR)
  {
    printf("[%d] Unable to create handle for device\n", tid);
    return NULL;
  }

  printf("[%d] cdev: %d\n", tid, cdev);

  if(set_key(cdev, a, b) == ERROR){
    printf("Unable to set key\n");
    return NULL;
  }

  if(set_config(cdev, DMA, UNSET) == ERROR){
    printf("Unable to set config\n");
    return NULL;
  }

  if(set_config(cdev, INTERRUPT, SET) == ERROR){
    printf("Unable to set config\n");
    return NULL;
  }

  void *mmap_addr = map_card(cdev, MAP_SIZE);
  printf("Address returned [USER]: %lx\n", (unsigned long) mmap_addr);
  if(mmap_addr == NULL){
    printf("Device Mapping failed\n");
    return NULL;
  }

  char* device_mmap_address = (char*) mmap_addr;
  unsigned long int id = *((int*)device_mmap_address);
  device_mmap_address[0] = 'j';
  printf("[0] : %c\n", device_mmap_address[0]);
  memcpy(&id, device_mmap_address-0xa8,4);
	printf("Identification code: %lx\n", id);

  memcpy((char*)device_mmap_address, op_text, MAP_SIZE);

  printf("[%d] Original Text: %s\n",tid, device_mmap_address);

  encrypt(cdev, device_mmap_address, MAP_SIZE, 1);
  // memcpy(op_text, (char*) device_mmap_address, MAP_SIZE);
  printf("[%d] Encrypted Text: %s\n\n\n", tid, device_mmap_address);

  decrypt(cdev, device_mmap_address, MAP_SIZE, 1);
  printf("Decrypted Text: %s\n\n\n", (char*) device_mmap_address);

  close_handle(cdev);
  return NULL;
}


int main()
{
  int tids[NUM_THREADS];
  pthread_t threads[NUM_THREADS];
  int i;
  printf("Creating threads...\n");
  for(i =0; i < NUM_THREADS; i++) {
    tids[i] = i+1;
    pthread_create(&threads[i], NULL, run, &tids[i]);
  }

  printf("Waiting for threads...\n");
  for(i=0; i < NUM_THREADS; i++)
    pthread_join(threads[i], NULL);
  
  return 0;
}