# Primeiro estágio: Construção da aplicação
FROM maven:3.8.8-eclipse-temurin-17 AS build

WORKDIR /app

# Instala o Git no contêiner
RUN apt-get update && apt-get install -y git

# Copia o arquivo pom.xml e baixa as dependências do projeto
COPY pom.xml .
RUN mvn dependency:resolve

# Agora copia o código-fonte
COPY src ./src

# Executa a build do projeto
RUN mvn clean package -DskipTests -X

# Segundo estágio: Imagem final para rodar a aplicação
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Copia o JAR gerado no primeiro estágio para a imagem final
COPY --from=build /app/target/*.jar /app/app.jar

# Expõe a porta 8080
EXPOSE 8080

# Comando para rodar a aplicação
CMD ["java", "-jar", "/app/app.jar"]
