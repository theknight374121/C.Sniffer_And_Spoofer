int main(){

char macStr[18];
char src_mac[3] = {0x69, 0x70, 0x3f};

snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x",
         src_mac[0], src_mac[1], src_mac[2]);
printf("%s",macStr);
 char dst_mac[3];

sscanf(macStr, "%02x:%02x:%02x", &dst_mac[0], &dst_mac[1], &dst_mac[2]);
snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x",
         dst_mac[0], dst_mac[1], dst_mac[2]);
printf("%s",macStr);
/*
int counter;
for(counter=0;counter<3;counter++){
	printf(dst_mac[counter]+"\n"+src_mac[counter]);
}
//printf("%s\n %s", dst_mac, src_mac);
*/

return 0;


}
