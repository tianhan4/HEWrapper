#pragma once

namespace hewrapper {

class PlainTextBase {
public:
    virtual PlainTextBase() = 0;
    virtual ~PlainTextBase() = 0;

    PlainTextBase(cosnt PlainTextBase &copy) = default;
    PlainTextBase(PlainTextBase &&copy) = default;
    PlainTextBase& operator=(const PlainTextBase &assign) = default;
    PlainTextBase& operator =(PlainTextBase &&assign) = default;
}

} // namespace hewrapper