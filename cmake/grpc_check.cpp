#include <grpcpp/grpcpp.h>
int main() {
  grpc::CreateChannel("127.0.0.0:1234", grpc::InsecureChannelCredentials());
  return 0;
}