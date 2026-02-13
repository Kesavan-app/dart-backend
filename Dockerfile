FROM dart:stable

WORKDIR /app

COPY pubspec.yaml pubspec.lock ./
RUN dart pub get

COPY . .

EXPOSE 8080

CMD ["dart", "server.dart"]
