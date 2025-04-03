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

O programa tem como objetivo validar se o *input* do utilizador tem o formato de um endereço IP válido, ou seja, se é uma *string* do tipo `A.B.C.D`, em que `A`, `B`, `C` e `D` são números naturais. Para o efeito, a função `check_ip()` verifica se o *input* contém apenas dígitos e exatamente três `.`, retornando `1` se e só nesse caso. Caso contrário - por exemplo, se o *input* contiver um número de `.` diferente de 3 ou se contiver caracteres que não sejam dígitos nem `.` -, então a função retorna `0`. Note-se que a função não verifica se o endereço IP é um valor válido (entre `0.0.0.0` e `255.255.255.255`), mas apenas se tem o formato esperado.

Assim sendo, `8.8.8.8`, `127.0.0.1` e `255.255.255.255` são considerados endereços IP com o formato correto, mas `999.999.999.999` também o é, embora não seja um endereço IP válido. Os *outputs* para estes *inputs* observam-se na imagem abaixo.

![Exemplos de Execução Benignos](/Lab2/images/benign-examples.png)

Este código apresenta uma vulnerabilidade de *buffer overflow*, visto que se o *input* do utilizador - fornecido como primeiro argumento do programa (`argv[1]`) - tiver o formato de um endereço IP válido, ou seja, a função `check_ip()` retornar `1`, então esse valor é copiado pela função `strcpy()` para o *array* `str` de tamanho fixo 16, não se verificando se o tamanho do *input* é menor do que o tamanho do *array*, portanto, permitindo que os limites da memória alocada para o *array* `str` sejam ultrapassados.
Como tal, um atacante pode inserir um *input* com um formato de um endereço IP válido, mas com comprimento superior a 16 *bytes*, de maneira a escrever indevidamente por cima de memória pertencente à *stack*, realizando um ataque de *buffer overflow* na *stack*.

Efetivamente, as execuções seguintes demonstram a ocorrência de *segmentation faults* quando o *input* fornecido ao programa cumpre o formato de um endereço IP válido e é suficientemente maior do que o tamanho do *buffer* ao ponto de escrever por cima de zonas de memórias não alocadas ao processo em execução. Por exemplo, os *inputs* `1234567.1234567.1234567.1234567`, `0.0.0.01234567890123456789` e `888888.888888.888888.888888` evidenciam esta vulnerabilidade.

![Exemplos de Execução Maliciosos](/Lab2/images/malign-examples.png)

Assim, como o programa vulnerável só *crasha* - originando uma vulnerabilidade de segurança - perante determinados *inputs*, mas não todos, é interessante testá-lo com ferramentas de *fuzzing black-box*, ferramentas de execução simbólica e ferramentas de *fuzzing grey-box*.

## Ferramentas de *Fuzzing Black-Box*

As ferramentas de *fuzzing black-box* testam o funcionamento do programa sem qualquer conhecimento sobre o seu código-fonte. Deste modo, são um bom ponto de partida para a análise do código em causa.

### Radamsa

O ***Radamsa*** é uma ferramenta de *fuzzing black-box* que gera *inputs* aleatórios para o programa ao realizar mutações sobre o *input* que lhe é fornecido. Como o ***Radamsa*** não é, por si só, uma *framework* de teste, é necessário desenvolver um *script* com a lógica de teste para ser possível gerar casos de teste contra a aplicação.

No entanto, foi recomendado não executar o ***Radamsa*** contra o programa em causa.

### Blab

O ***Blab*** é outra ferramenta de *fuzzing black-box*, que gera dados de acordo com gramáticas. Ou seja, é um *fuzzer* baseado em geração, ao qual deve ser fornecida uma gramática para definir os casos de teste a serem gerados para execução.

Assim, tendo em conta o programa em questão, foi criado o *script* `fuzz.py`, contendo o código abaixo.

```python
import subprocess
import sys

if len(sys.argv) < 5:
    print("Usage: fuzz.py <target> <n> <seed> <regex>")
    sys.exit(1)

target = sys.argv[1]
n = int(sys.argv[2])
seed = int(sys.argv[3])
regex = sys.argv[4]

for i in range(n):
    print(i, "/", n)

    fuzzer = subprocess.Popen(["blab", "-s", str(seed), "-e", regex], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    inp, err = fuzzer.communicate()
    inp = inp.decode().strip()
    print("Input:", inp)

    fuzzee = subprocess.Popen([target, inp], stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    out, err = fuzzee.communicate()
    print("Output:", out.decode())

    if fuzzee.returncode != 0:
        print("Crash! Return code:", fuzzee.returncode)
        if fuzzee.returncode == -11:
            print("SEGMENTATION FAULT")
        break
    
    seed += 1
```

O *script* `fuzz.py` recebe quatro argumentos do utilizador: o programa-alvo, o número máximo de *outputs* a gerar pelo ***Blab***, a semente de aleatoriedade para a geração desses *outputs* e a expressão regular que define a gramática da linguagem dos mesmos. Assim, o *script* faz com que o ***Blab*** gere *outputs* de acordo com determinadas regras, que são submetidos como *inputs* ao programa-alvo. Se o programa-alvo *crashar*, o *script* termina a execução e dá nota desse facto, destacando caso a falha ocorrida tenha sido uma *segmentation fault*.

Portanto, é possível testar a capacidade de este *script* detetar falhas de segurança no programa `ip.c`, fornecendo-lhe algumas expressões regulares para gerar *inputs*/*outputs*. Em todos os casos, a semente de aleatoriedade foi `10` e o número de iterações/tentativas foi limitado a `100`, no máximo.

Em primeiro lugar, experimentou-se a expressão regular `([0-9] | ".")*`, que gera um número arbitrário de dígitos e/ou pontos. O resultado inicial da execução apresenta-se abaixo.

![Blab](/Lab2/images/blab-1.png)

Como seria de esperar, esta execução não detetou nenhuma *segmentation fault*, visto que a probabilidade de a expressão regular fornecida como *input* gerar *strings* com exatamente três pontos e tamanho maior do que o *buffer* alocado é extremamente reduzida.

Em segundo lugar, testou-se a expressão regular `(([0-9])* ".")*`. Esta expressão gera dígitos seguidos de pontos, um número arbitrário de vezes. Parte do *output* mostra-se na imagem seguinte.

![Blab](/Lab2/images/blab-2.png)
![Blab](/Lab2/images/blab-3.png)

Desta vez, na 64ª iteração, a expressão regular originou um valor com o formato de um endereço IP válido, mas tamanho superior à memória alocada, o que causou um *buffer overflow*, portanto, uma *segmentation fault*. Este comportamento foi devidamente capturado pelo *script*, como se evidencia na segunda captura de ecrã acima exposta.

Por último, foi fornecida ao *script* a expressão regular `[0-9]+ "." [0-9]+ "." [0-9]+ "." [0-9]+`, que é a forma correta de gerar endereços IP, respeitando o seu formato, tendo resultado no seguinte *output* do programa.

![Blab](/Lab2/images/blab-4.png)
![Blab](/Lab2/images/blab-5.png)

Ora, esta execução resultou imediatamente numa *segmentation fault*, uma vez que o primeiro *input* gerado teve logo tamanho superior ao *buffer* alocado para o endereço IP. Efetivamente, era extremamente provável que isto sucedesse rapidamente, tendo em conta que a expressão regular de *input* só gera *strings* com o formato de endereços IP válidos, de modo que bastaria que o número de dígitos fosse maior do que o esperado, como se verificou.

#### Conclusão

Assim, o ***Blab*** foi capaz de detetar a vulnerabilidade em causa. A capacidade de o ***Blab*** detetar esta vulnerabilidade depende unicamente da gramática fornecida: se a linguagem gerada pela gramática - neste caso, expressão regular - contiver algum *input* que cause uma *segmentation fault*, então é possível que o ***Blab*** gere esse caso, tal como sucedeu. Evidentemente, a gramática é definida como parâmetro pelo Engenheiro de *Software*, pelo que quão mais ajustada estiver à realidade do programa em causa, maior a probabilidade de sucesso.

Para facilitar a execução do ***Blab***, foi desenvolvido o *script* `fuzz.py`, que permite gerar múltiplos *inputs*/*outputs* perante os quais testar o programa-alvo, retornando no caso de ser detetada uma *segmentation fault*, que pode representar uma vulnerabilidade. Neste *script*, é essencial configurar adequadamente o parâmetro `-e` da ferramenta ***Blab***, por ser este que define a gramática a utilizar para testar o programa. No caso exemplificado, a gramática consistiu numa expressão regular para o formato de endereços IP.

## Ferramentas de Execução Simbólica

### KLEE

## Ferramentas de *Fuzzing Grey-Box*

### AFL
