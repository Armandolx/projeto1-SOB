/**
 * @file   testebbchar.c
 * @author Derek Molloy
 * @date   7 April 2015
 * @version 0.1
 * @brief  A Linux user space program that communicates with the ebbchar.c LKM. It passes a
 * string to the LKM and reads the response from the LKM. For this example to work the device
 * must be called /dev/ebbchar.
 * @see http://www.derekmolloy.ie/ for a full description and follow-up descriptions.
*/
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int main(){
   int ret, fd;
   char stringToSend[BUFFER_LENGTH];
   printf("Starting device test code example...\n");
   fd = open("/dev/ebbchar", O_RDWR);             // Open the device with read/write access
   if (fd < 0){
      perror("Failed to open the device...");
      return errno;
   }
   printf("Digite o comando para cifrar tal como:\n");
   printf("c + <string a ser cifrada>\n");
   printf("d + <string a ser decifrada>\n");
   printf("h + <string para exibição do resumo criptográfico hash>\n");
   scanf("%[^\n]%*c", stringToSend);                // Read in a string (with spaces)
   
   if(stringToSend[0] == 'c' || stringToSend[0] == 'd' || stringToSend[0] == 'h'){
      if (stringToSend[1] == ' ')
      {
         printf("comando ok\n");
      }
      else{
         printf("comando inválido\n");
         return 1;
      }
   }
   else{
      printf("comando inválido\n");
      return 1;
   }
     // printf("Verifique o formato do comando inserido \n");
   
   printf("Comando recebido: [%s].\n", stringToSend);
   ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
   if (ret < 0){
      perror("Falha ao mandar mensagem para o device.");
      return errno;
   }

   printf("Pressione enter para efetuar leitura do device...\n");
   getchar();

   printf("Lendo do device...\n");
   ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
   if (ret < 0){
      perror("Falha ao ler mensagem do device.");
      return errno;
   }
   printf("Mensagem recebida: [%s]\n", receive);
   printf("fim\n");
   return 0;
}

