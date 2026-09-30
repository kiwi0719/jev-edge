FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /jev-shim .

FROM gcr.io/distroless/static-debian12
COPY --from=build /jev-shim /jev-shim
EXPOSE 9001
ENTRYPOINT ["/jev-shim"]
