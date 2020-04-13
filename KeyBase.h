#pragma once

namespace hewrapper {

class KeyBase {
public:
    virtual KeyBase() = default;
    virtual ~KeyBase() = default;
}

class PubKeyBase : public KeyBase {
    virtual PubKeyBase() = default;
    virtual ~PubKeyBase() = default;
}

class PrivateKeyBase : public KeyBase {
    virtual PrivateKeyBase() = default;
    virtual ~PrivateKeyBase() = default;
}

} // namespace hewrapper