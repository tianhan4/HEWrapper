#pragma once

namespace hewrapper {

class KeyBase {
public:
    virtual KeyBase() = 0;
    virtual ~KeyBase() = 0;
}

class PubKeyBase : public KeyBase {
    virtual PubKeyBase() = 0;
    virtual ~PubKeyBase() = 0;
}

class PrivateKeyBase : public KeyBase {
    virtual PrivateKeyBase() = 0;
    virtual ~PrivateKeyBase() = 0;
}

} // namespace hewrapper