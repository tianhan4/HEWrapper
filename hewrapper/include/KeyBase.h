#pragma once

namespace hewrapper {

class KeyBase {
public:
    KeyBase();
    ~KeyBase();
};

class PubKeyBase : public KeyBase {
public:
    PubKeyBase();
    ~PubKeyBase();
};

class PrivateKeyBase : public KeyBase {
public:
    PrivateKeyBase();
    ~PrivateKeyBase();
};

} // namespace hewrapper