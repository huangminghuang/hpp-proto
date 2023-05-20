#pragma once
#include <google/protobuf/descriptor.pb.hpp>
#include <iostream>
namespace hpp::proto {

template <typename FlatMap> void reserve(FlatMap &m, std::size_t s) {
  typename FlatMap::key_container_type keys;
  typename FlatMap::mapped_container_type values;
  keys.reserve(s);
  values.reserve(s);
  m.replace(std::move(keys), std::move(values));
}

template <typename AddOns> struct descriptor_pool {
  struct enum_descriptor_t;
  struct message_descriptor_t;
  using field_type_ptr_t = std::variant<std::monostate, message_descriptor_t *, enum_descriptor_t *>;

  struct field_descriptor_t : AddOns::template field_descriptor<field_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::FieldDescriptorProto *proto;
    message_descriptor_t *parent;
    field_type_ptr_t type;
    field_descriptor_t(const google::protobuf::FieldDescriptorProto &proto, const std::string &parent_name,
                       field_type_ptr_t type)
        : AddOns::template field_descriptor<field_descriptor_t>(proto, parent_name), proto(&proto), type(type) {}
  };

  struct oneof_descriptor_t : AddOns::template oneof_descriptor<oneof_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::OneofDescriptorProto *proto;
    std::vector<field_descriptor_t *> fields;
    oneof_descriptor_t(const google::protobuf::OneofDescriptorProto &proto)
        : AddOns::template oneof_descriptor<oneof_descriptor_t>(proto), proto(&proto) {}
  };

  struct enum_descriptor_t : AddOns::template enum_descriptor<enum_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::EnumDescriptorProto *proto;
    enum_descriptor_t(const google::protobuf::EnumDescriptorProto &proto)
        : AddOns::template enum_descriptor<enum_descriptor_t>(proto), proto(&proto) {}
  };

  struct message_descriptor_t : AddOns::template message_descriptor<message_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::DescriptorProto *proto;
    std::vector<enum_descriptor_t *> enums;
    std::vector<field_descriptor_t *> fields;
    std::vector<message_descriptor_t *> messages;
    std::vector<oneof_descriptor_t *> oneofs;
    std::vector<field_descriptor_t *> extensions;
    flat_map<uint32_t, field_descriptor_t *> extended_fields;

    message_descriptor_t(const google::protobuf::DescriptorProto &proto)
        : AddOns::template message_descriptor<message_descriptor_t>(proto), proto(&proto) {}
  };

  struct file_descriptor_t : AddOns::template file_descriptor<file_descriptor_t> {
    using pool_type = descriptor_pool;
    const google::protobuf::FileDescriptorProto *proto;
    std::vector<message_descriptor_t *> messages;
    std::vector<enum_descriptor_t *> enums;
    std::vector<field_descriptor_t *> extensions;

    file_descriptor_t(const google::protobuf::FileDescriptorProto &proto)
        : AddOns::template file_descriptor<file_descriptor_t>(proto), proto(&proto) {}
  };

  struct descriptor_counter {
    uint32_t files = 0;
    uint32_t messages = 0;
    uint32_t fields = 0;
    uint32_t oneofs = 0;
    uint32_t enums = 0;

    descriptor_counter(const std::vector<google::protobuf::FileDescriptorProto> &proto_files) {
      files = proto_files.size();

      for (auto &f : proto_files) {
        count(f.message_type);
        enums += f.enum_type.size();
        fields += f.extension.size();
      }
    }

    void count(const std::vector<google::protobuf::DescriptorProto> &proto_messages) {
      messages += proto_messages.size();
      for (auto &m : proto_messages) {
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
  flat_map<std::string, message_descriptor_t*> message_map;
  flat_map<std::string, enum_descriptor_t*> enum_map;

  descriptor_pool(const std::vector<google::protobuf::FileDescriptorProto> &proto_files) {

    descriptor_counter counter(proto_files);
    files.reserve(counter.files);
    messages.reserve(counter.messages);
    enums.reserve(counter.enums);
    oneofs.reserve(counter.oneofs);
    fields.reserve(counter.fields);
    reserve(file_map, counter.files);
    reserve(message_map, counter.messages);
    reserve(enum_map, counter.enums);

    for (auto &proto : proto_files) {
      if (proto.name) {
        build(files.emplace_back(proto));
      }
    }

    for (auto [name, msg] : message_map) {
      build_fields(*msg, name);
      build_extensions(*msg, name);
    }

    for (auto [name, f] : file_map) {
      build_extensions(*f, f->proto->package.value_or(""));
    }

    assert(messages.size() == counter.messages);
  }

  void build(file_descriptor_t &descriptor) {
    file_map.try_emplace(*descriptor.proto->name, &descriptor);
    descriptor.messages.reserve(descriptor.proto->message_type.size());
    std::string package = descriptor.proto->package.value_or("");
    for (auto &proto : descriptor.proto->message_type) {
      assert(proto.name.has_value());
      std::string name = package.size() ? "." + package + "." + *proto.name : "." +  *proto.name;
      auto &message = messages.emplace_back(proto);
      build(message, name);
      descriptor.messages.push_back(&message);
    }

    descriptor.enums.reserve(descriptor.proto->enum_type.size());
    for (auto &proto : descriptor.proto->enum_type) {
      assert(proto.name.has_value());
      std::string name = package.size() ? "." + package + "." + *proto.name : *proto.name;
      auto &e = enums.emplace_back(proto);
      enum_map.try_emplace(name, &e);
      descriptor.enums.push_back(&e);
    }
  }

  void build(message_descriptor_t &descriptor, const std::string &scope) {
    message_map.try_emplace(scope, &descriptor);
    descriptor.messages.reserve(descriptor.proto->nested_type.size());
    for (auto &proto : descriptor.proto->nested_type) {
      assert(proto.name.has_value());
      std::string name = scope + "." + *proto.name;
      auto &message = messages.emplace_back(proto);
      build(message, name);
      descriptor.messages.push_back(&message);
    }

    descriptor.enums.reserve(descriptor.proto->enum_type.size());
    for (auto &proto : descriptor.proto->enum_type) {
      assert(proto.name.has_value());
      std::string name = scope + "." + *proto.name;
      auto &e = enums.emplace_back(proto);
      enum_map.try_emplace(name, &e);
      descriptor.enums.push_back(&e);
    }

    descriptor.oneofs.reserve(descriptor.proto->oneof_decl.size());
    for (auto &proto : descriptor.proto->oneof_decl) {
      auto &oneof = oneofs.emplace_back(proto);
      descriptor.oneofs.push_back(&oneof);
    }
  }

  template <typename FlatMap>
  typename FlatMap::mapped_type find_type(FlatMap &types, const std::string &qualified_name) {
    auto itr = types.find(qualified_name);
    assert(itr != types.end() && "unable to find type");
    return itr->second;
  }

  field_type_ptr_t find_type_ptr(google::protobuf::FieldDescriptorProto::Type type, const std::string &qualified_name) {
    using enum google::protobuf::FieldDescriptorProto::Type;
    if (type == TYPE_MESSAGE)
      return find_type(message_map, qualified_name);
    else if (type == TYPE_ENUM)
      return find_type(enum_map, qualified_name);
    [[unlikely]] return {};
  }

  void build_fields(message_descriptor_t &descriptor, const std::string &qualified_name) {
    descriptor.fields.reserve(descriptor.proto->field.size());
    for (auto &proto : descriptor.proto->field) {
      if (proto.type.has_value()) {
        auto field_type =
            proto.type_name.has_value() ? find_type_ptr(*proto.type, *proto.type_name) : field_type_ptr_t{};
        auto &field = fields.emplace_back(proto, qualified_name, field_type);
        descriptor.fields.push_back(&field);
        if (proto.oneof_index.has_value()) {
          descriptor.oneofs[*proto.oneof_index]->fields.push_back(&field);
        }
      }
    }
  };

  void build_extensions(auto &parent, const std::string &scope) {
    for (auto &proto : parent.proto->extension) {
      if (proto.type.has_value()) {
        auto field_type =
            proto.type_name.has_value() ? find_type_ptr(*proto.type, *proto.type_name) : field_type_ptr_t{};
        auto &field = fields.emplace_back(proto, scope, field_type);
        parent.extensions.push_back(&field);
        if (proto.extendee.has_value()) {
          auto extendee = find_type(message_map, *proto.extendee);
          assert(field.proto->number);
          extendee->extended_fields.try_emplace(*field.proto->number, &field);
        }
      }
    }
  }
};
} // namespace hpp::proto
