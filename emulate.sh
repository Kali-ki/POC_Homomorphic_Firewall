g++ client.cpp utils.cpp -o client.elf -ltfhe-spqlios-fma
g++ server.cpp utils.cpp -o server.elf -ltfhe-spqlios-fma

echo "1 - Initialize\n"
./client.elf initialize
echo "\n2 - Analyze\n"
./client.elf analyze
echo "\n3 - Proceed\n"
./server.elf
echo "\n4 - Result\n"
./client.elf result
