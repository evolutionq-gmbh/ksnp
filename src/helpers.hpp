#pragma once

#include <string_view>

namespace ksnp
{

class zstring_view : public std::string_view
{
public:
    explicit constexpr zstring_view(std::string_view str) : std::string_view(str)
    {}

    [[nodiscard]] auto c_str() const noexcept -> char const *
    {
        return this->data();
    }
};

constexpr auto operator""_zsv(char const *str, size_t len) noexcept -> zstring_view
{
    return zstring_view{
        std::string_view{str, len}
    };
}

// helper type for the visitor
template<class... Ts>
struct overloads : Ts... {
    using Ts::operator()...;
};

}  // namespace ksnp

#define CATCH_ALL                                      \
    catch (ksnp::exception & e)                        \
    {                                                  \
        return e.code();                               \
    }                                                  \
    catch (ksnp::protocol_exception &)                 \
    {                                                  \
        return ksnp_error::KSNP_E_PROTOCOL_ERROR;      \
    }                                                  \
    catch (ksnp::version_exception &)                  \
    {                                                  \
        return ksnp_error::KSNP_E_UNSUPPORTED_VERSION; \
    }                                                  \
    catch (std::bad_alloc &)                           \
    {                                                  \
        return ksnp_error::KSNP_E_NO_MEM;              \
    }                                                  \
    catch (...)                                        \
    {                                                  \
        return ksnp_error::KSNP_E_UNKNOWN;             \
    }
