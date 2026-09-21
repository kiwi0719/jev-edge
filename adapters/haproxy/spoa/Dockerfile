FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /jev-spoa .
FROM alpine:3.20
COPY --from=build /jev-spoa /usr/local/bin/jev-spoa
ENTRYPOINT ["jev-spoa"]
