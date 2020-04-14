#pragma once

#include <KeyBase.h>
#include <TextBase.h>

namespace hewrapper {

class HEBase {
public:
    virtual HEBase() = 0;
    virtual HEBase(const PubKeyBase &k, const PlainTextBase &val) = 0;
    virtual ~HEBase() = default;

    virtual PlainTextBase decrypt(const PrivateKeyBase &k) = 0;

    HEBase(const HEBase &copy) = default;
    HEBase(HEBase &&copy) = default;
    
    // HE operation
    virtual HEBase& operator=(const HEBase &b) = 0;
    virtual HEBase& operator+(const HEBase &b) = 0;
    virtual HEBase& operator-(const HEBase &b) = 0;
    virtual HEBase& operator*(const HEBase &b) = 0;
    virtual HEBase& operator+(const PlainTextBase &b) = 0;
    virtual HEBase& operator-(const PlainTextBase &b) = 0;
    virtual HEBase& operator*(const PlainTextBase &b) = 0;

    virtual HEBase& operator+=(const HEBase &b) = 0;
    virtual HEBase& operator-=(const HEBase &b) = 0;
    virtual HEBase& operator*=(const HEBase &b) = 0;
    virtual HEBase& operator+=(const PlainTextBase &b) = 0;
    virtual HEBase& operator-=(const PlainTextBase &b) = 0;
    virtual HEBase& operator*=(const PlainTextBase &b) = 0;
} // class HEBase

} // namespace hewrapper