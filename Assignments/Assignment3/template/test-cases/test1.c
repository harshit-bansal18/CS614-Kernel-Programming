#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>
#include <pthread.h>

#define NUM_THREADS 100

void *run(void *arg) {
  int tid = *(int*)arg;
  printf("starting thread %d...\n", tid);
  DEV_HANDLE cdev;
  char msg[20];
  char op_text[16];
  KEY_COMP a=16 * (tid%16), b=17;
  printf("[Tid: %d] Keys a: %d, Key b: %d\n", tid, a, b);
  // uint64_t size = sprintf(msg, "Hello CS730%d!",tid);
  uint64_t size = sprintf(msg, "Hello CS730%d!\n", tid);
  // uint64_t size = strlen(msg);
  printf("[%d] calling create handle\n", tid);
  strcpy(op_text, msg);
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

  if(set_config(cdev, DMA, SET) == ERROR){
    printf("Unable to set config\n");
    return NULL;
  }

  if(set_config(cdev, INTERRUPT, SET) == ERROR){
    printf("Unable to set config\n");
    return NULL;
  }

  printf("[%d] Original Text: %s\n",tid, msg);

  encrypt(cdev, op_text, size, 0);
  printf("[%d] Encrypted Text: %s\n", tid, op_text);

  decrypt(cdev, op_text, size, 0);
  printf("Decrypted Text: %s\n", op_text);

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