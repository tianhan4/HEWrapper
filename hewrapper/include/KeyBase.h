#pragma once

namespace hewrapper {

class KeyBase {
public:
    KeyBase() = default;
    ~KeyBase() = default;
};

class PubKeyBase : public KeyBase {
public:
    PubKeyBase() = default;
    ~PubKeyBase() = default;
};

class PrivateKeyBase : public KeyBase {
public:
    PrivateKeyBase() = default;
    ~PrivateKeyBase() = default;
};

} // namespace hewrapper