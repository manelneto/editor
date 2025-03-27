# Lab 2 - Testing for Security

O programa escolhido para analisar é o `ip.c`, disponibilizado na pasta `Lab2`.

## `ip.c`

O ficheiro `ip.c` contém o código abaixo.

```c
#define MAX_SIZE 16

int check_ip(const char *ip) {
    int dots = 0;
    for (int i = 0; ip[i]; i++) {
        if (ip[i] == '.')
            dots++;
        else if (!isdigit(ip[i]))
            return 0;
    }
    return dots == 3;
}

int main(int argc, char *argv[]) {
    char buffer[MAX_SIZE] = {0};

    if (argc != 2) {
        printf("Usage: %s <IP>\n", argv[0]);
        return 1;
    }

    if (check_ip(argv[1])) {
        strcpy(buffer, argv[1]);                        /* FLAW */
        printf("Valid IP: %s\n", buffer);
    } else {
        printf("Invalid IP\n");
    }

    return 0;
}
```

O programa tem como objetivo validar se o *input* do utilizador tem o formato de um endereço IP válido, ou seja, se é uma *string* do tipo `A.B.C.C`, em que `A`, `B`, `C` e `D` são números naturais. Para o efeito, a função `check_ip()` verifica se o *input* contém apenas dígitos e exatamente três `.`, retornando `1` se e só nesse caso. Caso contrário - por exemplo, se o *input* contiver um número de `.` diferente de 3 ou se contiver caracteres que não sejam dígitos nem `.` -, então a função retorna `0`. Note-se que a função não verifica se o endereço IP é um valor válido (entre `0.0.0.0` e `255.255.255.255`), mas apenas se tem o formato esperado.

Assim sendo, `8.8.8.8`, `127.0.0.1`, `255.255.255.255` são considerados endereços IP com o formato correto, mas `999.999.999.999` também o é, embora não seja um endereço IP válido. Os *outputs* para estes *inputs* observam-se na imagem abaixo.

![Exemplos de Execução Benignos](/Lab2/images/benign-examples.png)

Este código apresenta uma vulnerabilidade de *buffer overflow*, visto que se o *input* do utilizador - fornecido como primeiro argumento do programa (`argv[1]`) - tiver o formato de um endereço IP válido, ou seja, a função `check_ip()` retornar `1`, então esse valor é copiado pela função `strcpy()` para o *array* `str` de tamanho fixo 16, não se verificando se o tamanho do *input* é menor do que o tamanho do *array*, portanto, permitindo que os limites da memória alocada para o *array* `str` sejam ultrapassados.
Como tal, um atacante pode inserir um *input* com um formato de um endereço IP válido, mas com comprimento superior a 16 *bytes*, de maneira a escrever indevidamente por cima de memória pertencente à *stack*, realizando um ataque de *buffer overflow* na *stack*.

Efetivamente, as execuções seguintes demonstram a ocorrência de *segmentation faults* quando o *input* fornecido ao programa cumpre o formato de um endereço IP válido e é suficientemente maior do que o tamanho do *buffer* ao ponto de escrever por cima de zonas de memórias não alocadas ao processo em execução. Por exemplo, os *inputs* `1234567.1234567.1234567.1234567`, `0.0.0.01234567890123456789` e `888888.888888.888888.888888` evidenciam esta vulnerabilidade.

![Exemplos de Execução Maliciosos](/Lab2/images/malign-examples.png)

### Ferramentas de *Fuzzing Black-Box*

#### Radamsa

#### Blab

### Ferramentas de Execução Simbólica

#### KLEE

### Ferramentas de *Fuzzing Grey-Box*

#### AFL
