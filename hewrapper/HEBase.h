#pragma once

#include <KeyBase.h>
#include <TextBase.h>

namespace hewrapper {

class HEBase {
public:
    virtual HEBase(PubKeyBase k, PlainTextBase val) = 0;
    virtual ~HEBase() = default;

    virtual PlainTextBase decrypt(PrivateKeyBase k) = 0;
    
    // HE operation
    virtual HEBase& operator++() = 0;
    virtual HEBase& operator--() = 0;

    virtual HEBase& operator=(const HEBase& b) = 0;
    virtual HEBase& operator+(const HEBase& b) = 0;
    virtual HEBase& operator-(const HEBase& b) = 0;
    virtual HEBase& operator*(const HEBase& b) = 0;
    virtual HEBase& operator/(const HEBase& b) = 0;
    virtual HEBase& operator+(const PlainTextBase& b) = 0;
    virtual HEBase& operator-(const PlainTextBase& b) = 0;
    virtual HEBase& operator*(const PlainTextBase& b) = 0;
    virtual HEBase& operator/(const PlainTextBase& b) = 0;

    virtual HEBase& operator+=(const HEBase& b) = 0;
    virtual HEBase& operator-=(const HEBase& b) = 0;
    virtual HEBase& operator*=(const HEBase& b) = 0;
    virtual HEBase& operator/=(const HEBase& b) = 0;
    virtual HEBase& operator+=(const PlainTextBase& b) = 0;
    virtual HEBase& operator-=(const PlainTextBase& b) = 0;
    virtual HEBase& operator*=(const PlainTextBase& b) = 0;
    virtual HEBase& operator/=(const PlainTextBase& b) = 0;
} // class HEBase

} // namespace hewrapper