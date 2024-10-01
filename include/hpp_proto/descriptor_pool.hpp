#pragma once
#include <cassert>
#include <google/protobuf/descriptor.pb.hpp>
#include <iostream>
namespace hpp::proto {

template <typename FlatMap>
void reserve(FlatMap &m, std::size_t s) {
  typename FlatMap::key_container_type keys;
  typename FlatMap::mapped_container_type values;
  keys.reserve(s);
  values.reserve(s);
  m.replace(std::move(keys), std::move(values));
}

// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
template <typename AddOns>
struct descriptor_pool {
  struct field_descriptor_t : AddOns::template field_descriptor<field_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::FieldDescriptorProto &proto;
    field_descriptor_t(const google::protobuf::FieldDescriptorProto &proto, const std::string &parent_name)
        : AddOns::template field_descriptor<field_descriptor_t>(proto, parent_name), proto(proto) {}
  };

  struct oneof_descriptor_t : AddOns::template oneof_descriptor<oneof_descriptor_t, field_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::OneofDescriptorProto &proto;
    explicit oneof_descriptor_t(const google::protobuf::OneofDescriptorProto &proto)
        : AddOns::template oneof_descriptor<oneof_descriptor_t, field_descriptor_t>(proto), proto(proto) {}
  };

  struct enum_descriptor_t : AddOns::template enum_descriptor<enum_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::EnumDescriptorProto proto;
    explicit enum_descriptor_t(const google::protobuf::EnumDescriptorProto &proto)
        : AddOns::template enum_descriptor<enum_descriptor_t>(proto), proto(proto) {}
  };

  struct message_descriptor_t : AddOns::template message_descriptor<message_descriptor_t, enum_descriptor_t,
                                                                    oneof_descriptor_t, field_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::DescriptorProto &proto;

    explicit message_descriptor_t(const google::protobuf::DescriptorProto &proto)
        : AddOns::template message_descriptor<message_descriptor_t, enum_descriptor_t, oneof_descriptor_t,
                                              field_descriptor_t>(proto),
          proto(proto) {}
  };

  struct file_descriptor_t : AddOns::template file_descriptor<file_descriptor_t, message_descriptor_t,
                                                              enum_descriptor_t, field_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::FileDescriptorProto &proto;

    explicit file_descriptor_t(const google::protobuf::FileDescriptorProto &proto)
        : AddOns::template file_descriptor<file_descriptor_t, message_descriptor_t, enum_descriptor_t,
                                           field_descriptor_t>(proto),
          proto(proto) {}
  };

  struct descriptor_counter {
    std::size_t files = 0;
    std::size_t messages = 0;
    std::size_t fields = 0;
    std::size_t oneofs = 0;
    std::size_t enums = 0;

    explicit descriptor_counter(const std::vector<google::protobuf::FileDescriptorProto> &proto_files)
        : files(proto_files.size()) {
      for (const auto &f : proto_files) {
        count(f.message_type);
        enums += f.enum_type.size();
        fields += f.extension.size();
      }
    }

    void count(const std::vector<google::protobuf::DescriptorProto> &proto_messages) {
      messages += proto_messages.size();
      for (const auto &m : proto_messages) {
        count(m.nested_type);
        enums += m.enum_type.size();
        fields += m.field.size() + m.extension.size();
        oneofs += m.oneof_decl.size();
      }
    }
  };

  std::vector<file_descriptor_t> files;
  std::vector<message_descriptor_t> messages;
  std::vector<enum_descriptor_t> enums;
  std::vector<oneof_descriptor_t> oneofs;
  std::vector<field_descriptor_t> fields;

  flat_map<std::string, file_descriptor_t *> file_map;
  flat_map<std::string, message_descriptor_t *> message_map;
  flat_map<std::string, enum_descriptor_t *> enum_map;

  explicit descriptor_pool(const std::vector<google::protobuf::FileDescriptorProto> &proto_files) {
    const descriptor_counter counter(proto_files);
    files.reserve(counter.files);
    messages.reserve(counter.messages);
    enums.reserve(counter.enums);
    oneofs.reserve(counter.oneofs);
    fields.reserve(counter.fields);
    reserve(file_map, counter.files);
    reserve(message_map, counter.messages);
    reserve(enum_map, counter.enums);

    for (const auto &proto : proto_files) {
      if (!proto.name.empty() && file_map.count(proto.name) == 0) {
        build(files.emplace_back(proto));
      }
    }

    for (auto [name, msg] : message_map) {
      build_fields(*msg, name);
      build_extensions(*msg, name);
    }

    for (auto [name, f] : file_map) {
      build_extensions(*f, f->proto.package);
    }

    assert(messages.size() == counter.messages);
  }

  void build(file_descriptor_t &descriptor) {
    file_map.try_emplace(descriptor.proto.name, &descriptor);
    const std::string package = descriptor.proto.package;
    for (auto &proto : descriptor.proto.message_type) {
      std::string const name = !package.empty() ? "." + package + "." + proto.name : "." + proto.name;
      auto &message = messages.emplace_back(proto);
      build(message, name);
      descriptor.add_message(message);
    }

    for (auto &proto : descriptor.proto.enum_type) {
      const std::string name = !package.empty() ? "." + package + "." + proto.name : proto.name;
      auto &e = enums.emplace_back(proto);
      enum_map.try_emplace(name, &e);
      descriptor.add_enum(e);
    }
  }

  void build(message_descriptor_t &descriptor, const std::string &scope) {
    message_map.try_emplace(scope, &descriptor);
    for (auto &proto : descriptor.proto.nested_type) {
      const std::string name = scope + "." + proto.name;
      auto &message = messages.emplace_back(proto);
      build(message, name);
      descriptor.add_message(message);
    }

    for (auto &proto : descriptor.proto.enum_type) {
      const std::string name = scope + "." + proto.name;
      auto &e = enums.emplace_back(proto);
      enum_map.try_emplace(name, &e);
      descriptor.add_enum(e);
    }

    for (auto &proto : descriptor.proto.oneof_decl) {
      descriptor.add_oneof(oneofs.emplace_back(proto));
    }
  }

  template <typename FlatMap>
  typename FlatMap::mapped_type find_type(FlatMap &types, const std::string &qualified_name) {
    auto itr = types.find(qualified_name);
    assert(itr != types.end() && "unable to find type");
    return itr->second;
  }

  void build_fields(message_descriptor_t &descriptor, const std::string &qualified_name) {
    for (auto &proto : descriptor.proto.field) {
      descriptor.add_field(fields.emplace_back(proto, qualified_name));
    }
  };

  void build_extensions(auto &parent, const std::string &scope) {
    for (auto &proto : parent.proto.extension) {
      parent.add_extension(fields.emplace_back(proto, scope));
    }
  }
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
} // namespace hpp::proto
