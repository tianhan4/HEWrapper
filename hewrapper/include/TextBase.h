#pragma once

namespace hewrapper {

class PlainTextBase {
public:
    PlainTextBase() = default;
    ~PlainTextBase() = default;

    PlainTextBase(const PlainTextBase &copy) = default;
    PlainTextBase(PlainTextBase &&copy) = default;
    PlainTextBase& operator=(const PlainTextBase &assign) = default;
    PlainTextBase& operator=(PlainTextBase &&assign) = default;
};

} // namespace hewrapper