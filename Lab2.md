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

Efetivamente, as execuções seguintes demonstram a ocorrência de *segmentation faults* quando o *input* fornecido ao programa cumpre o formato de um endereço IP válido e é suficientemente maior do que o tamanho do *buffer* ao ponto de escrever por cima de zonas de memórias não alocadas ao processo em execução. Por exemplo, os *inputs* `1234567.1234567.1234567.1234567`, `0.0.0.01234567890123456789` e `ech` evidenciam esta vulnerabilidade.

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

As ferramentas de execução simbólica permitem testar o programa com base nos diferentes caminhos de execução possíveis, aumentando a cobertura do código através da utilização de variáveis simbólicas, que representam os diversos valores que a variável concreta pode assumir. Por isso, estas ferramentas apresentam frequentemente um desempenho superior aos testes manuais e/ou aleatórios.

### KLEE

O ***KLEE*** é uma ferramenta de execução simbólica capaz de gerar automaticamente múltiplos *inputs* de teste de maneira a explorar uma grande quantidade de caminhos de execução. Contudo, como avaliar todas as execuções possíveis de um programa é um problema computacionalmente complexo, o ***KLEE*** limita a sua exploração a uma determinada profundidade.

Para testar o programa `ip.c` com o ***KLEE***, é necessário fazer ligeiras alterações ao código original, que se expõem de seguida.

```c
#include <klee/klee.h>

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

int main() {
    char input[32];
    klee_make_symbolic(input, sizeof(input), "input");
    input[31] = '\0';

    char buffer[MAX_SIZE] = {0};

    if (check_ip(input)) {
        strcpy(buffer, input);                          /* FLAW */
        printf("Valid IP: %s\n", buffer);
    } else {
        printf("Invalid IP\n");
    }

    return 0;
}
```

Em particular, é necessário incluir a biblioteca `klee.h` e, na função `main()`, substituir a utilização da variável `argv[1]` por uma nova variável `char input[32]`. Esta variável `input` é - através da chamada à função `klee_make_symbolic()` - definida como a variável simbólica do programa, de maneira a assumir vários valores possíveis em diferentes ramos de execução criados pelo ***KLEE***. Deste modo, pretende-se testar o comportamento do programa perante diferentes valores da variável `input`, na expectativa de que algum deles passe na verificação da função `check_ip()` e tenha tamanho suficiente para causar um *buffer overflow* e a consequente *segmentation fault*. Para isso, define-se o tamanho de `input` (32) para o dobro do tamanho da variável `buffer` (16).

A compilação e execução deste código ligeiramente modificado com o ***KLEE*** apresenta-se na imagem abaixo.

![KLEE](/Lab2/images/klee-1.png)
![KLEE](/Lab2/images/klee-2.png)
![KLEE](/Lab2/images/klee-3.png)

O comando de compilação `clang -I /home/klee/klee_src/include/ -emit-llvm -c -g -O0 -Xclang -disable-O0-optnone ip-klee.c` chama o compilador `clang` para compilar o ficheiro `ip-klee.c`. A *flag* `-I` adiciona o diretório `/home/klee/klee_src/include/` aos caminhos nos quais procurar *headers*, para encontrar a biblioteca incluída `klee.h`. De seguida, a *flag* `-emit-llvm` faz com que o código gerado não seja binário, mas sim uma representação intermédia em LLVM, produzindo um ficheiro com a extensão `.bc`. A *flag* `-c` evita que o compilador faça *link* do programa, `-g` inclui informações de *debug* que são úteis para ferramentas de execução simbólica e `-O0` desativa otimizações de compilação, de maneira a não reorganizar o código, preservando as suas propriedades para ser analisado pelo ***KLEE***. Finalmente, `-Xclang` passa os argumentos diretamente ao *frontend* do compilador e `-disable-O0-optnone` impede a adição automática do atributo `optnone` às funções, ao utilizar `-O0`. O comando `klee --libc=uclibc ip-klee.bc` executa a ferramenta ***KLEE*** contra o programa `ip-klee.bc`, substituindo as funções da biblioteca `libc` por uma implementação compilada de forma simbólica (`uclibc`).

Como se evidencia pelas imagens acima, o ***KLEE*** não conseguiu detetar a falha de segurança presente no código, uma vez que nenhum fluxo de execução seguido originou um *buffer overflow*. Isto sucedeu porque, apesar de a variável simbólica `input` tomar alguns valores correspondentes a endereços IP válidos em formato, nenhum desses casos teve tamanho suficiente para escrever por cima de memória não alocada. Deste modo, nenhuma das execuções do programa originou uma *segmentation fault*.

Note-se que os avisos lançados pelo ***KLEE*** no início da execução do programa não são impeditivos do seu correto funcionamento, mas meros indicadores sobre algumas chamadas a funções que não estão definidas no código analisado nem diretamente incluídas, pelo que não são suportadas. Não obstante este facto, o ***KLEE*** gerou 139742 testes, divididos em 28717 caminhos completamente executados e 111025 caminhos apenas parcialmente executados, aos quais correspondem 6369599 instruções. Contudo, nenhum destes ramos levou a um *buffer overflow*.

Esta incapacidade do ***KLEE*** em identificar o erro no programa pode ser comprovada através de uma análise dos testes gerados e armazenados no diretório `klee-last`. A título de exemplo, a imagem abaixo contém a execução de um dos testes.

![KLEE](/Lab2/images/klee-4.png)

Ora, neste teste em concreto o *input* gerado pelo ***KLEE*** foi `55..............................` que, não tendo o formato de um endereço IP válido, não alcança o ramo de execução que contém a vulnerabilidade de *buffer overflow*.

De maneira a automatizar a pesquisa pelos testes gerados para compreender melhor a razão pela qual nenhum dos *outputs* `Valid IP` resultou num *buffer overflow* e na consequente *segmentation fault*, pode aproveitar-se a biblioteca `lkleeRuntest`, criando um ciclo que corre os primeiros 10000 testes, através do comando `for i in $(seq -w 0 9999); do KTEST_FILE=klee-last/test00$i.ktest ./a.out done`, como se mostra na imagem seguinte.

![KLEE](/Lab2/images/klee-5.png)

Fazendo `grep "Valid IP:"` deste *output*, mostram-se apenas os casos que resultaram num endereço IP válido - que são os únicos que podem originar uma *segmentation fault* -, obtém-se o resultado seguinte.

![KLEE](/Lab2/images/klee-6.png)

Deste modo, confirma-se a razão pela qual o ***KLEE*** não detetou o erro de memória do programa: todos os *inputs* gerados com formato de um endereço IP válido não têm tamanho suficiente para exceder o *buffer* alocado para o seu armazenamento, de maneira que nunca acontece um caso de *buffer overflow*. Isto deve-se ao facto de o ***KLEE*** ir progressivamente aumentando o tamanho do valor gerado para a variável simbólica, mas ser necessário um tamanho superior a 16 *bytes* que, tendo em conta o número de combinações/permutações possíveis para a ordem dos caracteres em *inputs* de tamanhos menores, não é atingido/gerado em tempo útil.

#### Conclusão

Em suma, o ***KLEE*** não conseguiu detetar a vulnerabilidade existente no programa. A incapacidade em detetar esta vulnerabilidade reside no facto de o ***KLEE*** ser uma ferramenta de execução simbólica, projetada para testar múltiplos ramos/caminhos de execução, mas esta vulnerabilidade ocorrer apenas perante um *input* com um formato extremamente específico, dadas as restrições subjacentes à verificação do endereço IP. Como tal, por mais valores que a variável simbólica possa assumir, é improvável que algum deles seja um endereço IP válido e com tamanho superior ao da memória alocada, pelo que esta ferramenta se mostra incapaz de cumprir o efeito pretendido, a não ser que gere *inputs* seguindo determinadas regras gramaticais, como no caso anterior.

O código do programa original teve de ser ligeiramente modificado para converter a variável de *input* numa variável simbólica, de maneira a aproveitar as potencialidades do ***KLEE*** para instanciar diferentes valores concretos nesta variável, percorrendo os diversos caminhos de execução possíveis. Para esse efeito, utilizou-se a função `klee_make_symbolic()`. Todavia, nenhum dos valores assumidos pela variável foi capaz de *crashar* o programa e causar uma *segmentation fault*, deixando a vulnerabilidade de *buffer overflow* por detetar.

## Ferramentas de *Fuzzing Grey-Box*

As ferramentas de *fuzzing grey-box* são, tal como o nome indica, um misto entre as ferramentas de *fuzzing black-box* e as ferramentas de execução simbólica. Ou seja, estas ferramentas geram automaticamente *inputs* a fornecer ao programa a testar, mas com algum conhecimento interno para tentar maximizar o seu desempenho.

### AFL

O ***American Fuzzy Loop (AFL)*** é uma ferramenta de *fuzzing grey-box* que toma em consideração a cobertura do código atingida pelos *inputs* de teste de maneira a tomar decisões informadas sobre quais os *inputs* que devem sofrer mutações para, com maior probabilidade, maximizar a cobertura do código. Assim, o ***AFL*** consegue tirar proveito das capacidades de execução simbólica e de *fuzzing black-box*.

Para analisar o programa em causa com o ***AFL***, o código do ficheiro `ip.c` tem de ser ligeiramente modificado, resultando no excerto abaixo.

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

int main() {
    char buffer[MAX_SIZE] = {0};
    char input[32] = {0};

    fread(input, 1, sizeof(input) - 1, stdin);

    if (check_ip(input)) {
        strcpy(buffer, input);                          /* FLAW */
        printf("Valid IP: %s\n", buffer);
    } else {
        printf("Invalid IP\n");
    }

    return 0;
}
```

A única modificação necessária consiste em receber o *input* do programa via `stdin` em vez de via linha de comandos (`argv[1]`), visto que o ***AFL*** injeta os dados de teste através do *standard input* e não como argumentos.

Para executar o ***AFL*** é ainda necessário definir pelo menos um caso de teste inicial, a partir do qual serão gerados automaticamente novos casos de teste, através de mutações. Nesse sentido, foi criado o ficheiro `ip.txt` com um endereço IP válido, como se demonstra abaixo.

![AFL](/Lab2/images/afl-1.png)

Após isto, foi compilado o programa para o ***AFL*** com o comando `AFL_HARDEN=1 afl-clang-fast ip-afl.c -o ip-afl` e, posteriormente, foi lançado o ***AFL***, ao executar `afl-fuzz -i inputs -o out ./ip-afl`. A imagem abaixo mostra os resultados da execução.

![AFL](/Lab2/images/afl-2.png)
![AFL](/Lab2/images/afl-3.png)

Efetivamente, a execução do ***AFL*** mostra que a ferramenta foi capaz de identificar 4430 *inputs* que *crasharam* o programa, dos quais guardou um. Este *crash* foi encontrado ao realizar mutações sobre o *input* original fornecido para teste, sendo que o caso de teste em concreto que gerou a *crash* armazenada pode ser consultado em `out/default/crashes`, o que se realiza na imagem seguinte.

![AFL](/Lab2/images/afl-4.png)

Ora, o ficheiro guardado mostra que o *input* que *crashou* o programa foi `1.2.3.44444444444444444444444444444`, o que, efetivamente, tem um formato de endereço IP válido, mas tamanho superior à memória alocada para o *buffer*, pelo originou um *segmentation fault*. Deste modo, ao estender o *input* original válido `1.2.3.4`, o ***AFL*** foi capaz de gerar um teste que demonstrou a vulnerabilidade de *buffer overflow* do programa.

Note-se que o nome do ficheiro `id:000000,sig:06,src:000000,time:188,execs:1076,op:havoc,rep:1` traduz algumas informações relevantes sobre o mesmo, nomeadamente:

- `id:000000`, que significa que este *crash* é o primeiro encontrado;
- `sig:06`, que indica que o processo terminou a execução com o sinal 6 (`SIGABRT`);
- `src:000000`, que mostra que este caso foi gerado a partir do primeiro (e único) *input*;
- `time:188`, que representa o tempo, em segundos, decorrido até ao *crash*;
- `execs:1076`, que corresponde ao número total de execuções diferentes até ao *crash*;
- `op:havoc`, que demonstra que a mutação que levou ao *crash* foi realizada com a operação *havoc*, que consiste numa pesquisa aleatória intensa;
- `rep:1`, que evidencia que apenas um *input* causou este *crash*.

### Conclusão

Assim sendo, o ***AFL*** conseguiu detetar a vulnerabilidade de *buffer overflow* no código. Isto deve-se ao facto de o ***AFL*** ter sido capaz de fazer alterações/mutações ao *input* original, nomeadamente estendendo-o, de maneira a exceder a memória alocada para a variável que o armazena, causando uma consequente *segmentation fault*. Deste modo, ao receber um *input* válido para o programa em causa, a ferramenta de *fuzzing grey-box* realizou mutações sobre a mesma, seguindo diversas técnicas distintas, em particular *havoc*, até resultar num *crash* da execução do programa.

Para executar o ***AFL***, foi necessário fazer uma mínima alteração no código original, relativamente à forma como o *input* era enviado para o programa, bem como definir um caso de teste inicial, a partir do qual são geradas as mutações. Ora, como foi facilmente comprovável, este teste inicial não tem de ser sofisticado nem próximo dos casos que geram *segmentation faults*, visto que o ***AFL*** é capaz de o mutar devidamente até alcançar resultados satisfatórios, ou seja, *crashes*. A execução do ***AFL*** é extremamente simples, tendo em conta que só é necessário compilar o programa de forma a prepará-lo para a instrumentalização e, posteriormente, correr a ferramenta de *fuzzing grey-box* que, neste caso, detetou a vulnerabilidade de *buffer overflow*.

## Análise Global

Em suma, apresentam-se os resultados obtidos por todas as ferramentas de teste utilizadas com o propósito de detetar a vulnerabilidade de *buffer overflow* em causa.

|      **Categoria**      | **Ferramenta** | **Resultado** |
| ----------------------  | -------------- | ------------- |
| ***Fuzzing Black-Box*** | ***Radamsa***  |      N/A      |
| ***Fuzzing Black-Box*** |   ***Blab***   |      SIM      |
| **Execução Simbólica**  |   ***KLEE***   |      NÃO      |
| ***Fuzzing Grey-Box***  |   ***AFL***    |      SIM      |

No caso deste programa em particular, ambas as abordagens de *fuzzing* - tanto *black-box* (***Blab***) como *grey-box* (***AFL***) - foram capazes de detetar a vulnerabilidade existente, enquanto a ferramenta de execução simbólica (***KLEE***) não foi capaz de o fazer. No entanto, este facto não é, evidentemente, diretamente generalizável para todos os casos, apesar de existirem diferenças significativas entre ambas as abordagens.

Assim sendo, conclui-se que existem *tradeoffs* entre *fuzzing* e execução simbólica. Por um lado, o *fuzzing* gera *inputs* de forma mais fácil e eficiente, com menor custo computacional e exigindo poucas ou nenhumas alterações ao código, mas tem maior dificuldade em cobrir os diferentes caminhos de execução possíveis, a não ser que lhe seja fornecida alguma informação sobre o código a testar, seja uma gramática (como no caso do ***Radamsa***), seja um *input* inicial (para o ***AFL***). Por outro lado, a execução simbólica é capaz de ter uma maior cobertura do código mais facilmente, mas com um custo computacional mais elevado - subjacente ao cálculo dos diversos caminhos possíveis - e com a necessidade de realizar mais alterações ao código original, tornando-o o simbólico.

Portanto, o melhor das duas alternativas parece surgir no espaço intermédio entre ambas, com a utilização de *fuzzing grey-box*. Esta solução, em particular através do ***AFL***, permite seguir uma abordagem de *fuzzing* a partir de um *input* inicial, mas com a capacidade de explorar as diferentes execuções possíveis do programa de forma inteligente, através da utilização de heurísticas internas e de diferentes métodos/abordagens para a geração de novos casos de teste, explorados conforme o seu interesse. Assim, o *fuzzing grey-box* concilia a eficiência e simplicidade do *fuzzing black-box* com a capacidade de explorar diversos caminhos/fluxos de execução da execução simbólica, tornando-se uma solução particularmente interesse para testes no contexto de segurança.
