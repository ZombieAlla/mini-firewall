## 1. First, one should install the following library:
libnetfilter-queue-dev

it can be done with the command:
> sudo apt-get install libnetfilter-queue-dev

## 2. Compilation of the program should be done with the lnetfilter_queue library. 
For instance:
> gcc -o cap cap.c -lnetfilter_queue

## 3. Execution should be done in the following command:
>sudo ./cap $1 $2 $3 $4

where:

* $1 is the source ip address to filter by
* $2 is the port to filter by
* $3 is the number of packets to print to out.txt
* $4 is string to search in packet's payload

for instance: 
>sudo ./cap 123.123.123.123 53 6 com


## 4. The output will be in out.txt.

## 5. The code uses SHELL to set the firewall rules to set the kernel queue. If by some reason, the code fails, one must cancel the applied rules.

* Viewing iptables rules:
>sudo iptables --list

* Adding a rule to iptables:
>sudo iptables -A INPUT -j NFQUEUE --queue-num 0

* Removing a rule from iptables:
>sudo iptables -D INPUT -j NFQUEUE --queue-num 0

## 6.Brief Description of the implementation:
I took the given example nfqnl_test.c and modified it to fit the task. 
First I've learned how to use the iptables and read packages from kernel queue. Then I've added shell instructions to cap.c file. One in the start of the main program, to add a rule, and one in the end, to remove the rule from iptables.
Afterwards, I've added stop condition for the for loop in main, in order to be constrained by the given 3rd parameter-i, number of packets to print. I decided to store all the input in a global struct for an easy access to the given parameters.
I used the suggested pseudo code to supply the requirements. First, I've checked the ip header to compare the source ip address to the first parameter. Then, I've checked if it's a TCP or UDP packet and used it to extract the port. The Tricky part was to find the size of the payload without the headers. After doing so, the task was completed, As I could search the string in payload and print it to file.
