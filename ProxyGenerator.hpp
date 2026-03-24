#pragma once
// ============================================================
// ProxyGenerator.hpp — Method 3: C++ Class Reconstruction
//
// Translates Python build3.py into native C++.
// Parses MSVC undecorated names → reconstructs C++ classes →
// compiles → compares exports → patches missing → recompiles.
//
// Usage: ProxyGen::Build("target.dll")
// ============================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <regex>
#include "PEFile.hpp"

namespace ProxyGen {

// ============================================================
// Data structures
// ============================================================
struct ParsedExport {
    std::string original;
    std::string kind;       // vftable, auto_generated, static_data, c_function, constructor, destructor, method, operator_
    std::string access;     // public, protected, private, ""
    bool is_static = false;
    bool is_virtual = false;
    bool is_const = false;
    bool is_free_function = false;
    std::string return_type;
    std::string class_name;
    std::string method;
    std::string params_raw;
    DWORD ordinal = 0;
    std::string decorated;
    bool type_degraded = false; // true if any type was degraded (e.g. → void*), mangling will differ
};

// ============================================================
// Constants
// ============================================================
static const std::string WSTRING_VERBOSE =
    "class std::basic_string<wchar_t,struct std::char_traits<wchar_t>,class std::allocator<wchar_t> >";

static const std::set<std::string> SDK_STRUCTS = {
    "IUnknown","IDispatch","_CMSG_SIGNER_INFO","_iobuf","tagVARIANT",
    "HKEY__","IWbemClassObject","IWbemServices","IWbemObjectSink",
    "IEnumWbemClassObject","_CERT_CONTEXT","IStream","_FILETIME",
    "_SYSTEMTIME","_SECURITY_ATTRIBUTES","tagPROPVARIANT","_GUID",
    "wa_map_hasher","wa_map_equal_to",
    // Windows HANDLE types (DECLARE_HANDLE generates these)
    "HINSTANCE__","HWND__","HDC__","HBITMAP__","HBRUSH__","HFONT__",
    "HICON__","HMENU__","HMODULE__","HPEN__","HRGN__","HRSRC__",
    "HMONITOR__","HCURSOR__","HACCEL__","HDWP__","HGLOBAL__",
    "HTREEITEM__","HIMAGELIST__","HDESK__","HWINSTA__",
};

static const std::vector<std::string> UNKNOWN_TEMPLATES = {
    "WaAsyncIO","ATL","CComPtr","std::_List"
};

static const std::vector<std::string> EXTRA_FORWARD_DECLS = {
    "class IWaCryptoAES","class IWaCryptoRSA","class WaSignalLock",
    "class WaThirdPartyGateway",
};

// ============================================================
// String helpers
// ============================================================

static bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static bool endsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool contains(const std::string& s, const std::string& sub) {
    return s.find(sub) != std::string::npos;
}

static std::string replaceAll(std::string s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string collapseSpaces(const std::string& s) {
    std::string r;
    bool prev = false;
    for (char c : s) {
        if (c == ' ' || c == '\t') { if (!prev) { r += ' '; prev = true; } }
        else { r += c; prev = false; }
    }
    return trim(r);
}

// Remove all occurrences of a whole word
static std::string stripWord(const std::string& s, const std::string& word) {
    std::string result = s;
    size_t pos = 0;
    while ((pos = result.find(word, pos)) != std::string::npos) {
        // Check word boundaries
        bool left = (pos == 0 || !isalnum(result[pos-1]));
        bool right = (pos + word.size() >= result.size() || !isalnum(result[pos + word.size()]));
        if (left && right) {
            result.erase(pos, word.size());
            // Also remove trailing space
            while (pos < result.size() && result[pos] == ' ') result.erase(pos, 1);
        } else {
            pos += word.size();
        }
    }
    return result;
}

// Check if string matches pattern \w+::\w+::\w+ (3-level nesting)
static bool has3LevelNesting(const std::string& s) {
    // Look for word::word::word
    size_t i = 0;
    while (i < s.size()) {
        // Find start of a word
        if (!isalnum(s[i]) && s[i] != '_') { i++; continue; }
        size_t w1 = i;
        while (i < s.size() && (isalnum(s[i]) || s[i] == '_')) i++;
        if (i + 1 < s.size() && s[i] == ':' && s[i+1] == ':') {
            i += 2;
            if (i < s.size() && (isalnum(s[i]) || s[i] == '_')) {
                while (i < s.size() && (isalnum(s[i]) || s[i] == '_')) i++;
                if (i + 1 < s.size() && s[i] == ':' && s[i+1] == ':') {
                    i += 2;
                    if (i < s.size() && (isalnum(s[i]) || s[i] == '_'))
                        return true;
                }
            }
        }
    }
    return false;
}

// ============================================================
// simplify_type: convert MSVC verbose types to compilable C++
// ============================================================
// simplified: set to true if type was degraded to void* (mangling will differ)
static std::string simplifyType(const std::string& input, bool* degraded = nullptr) {
    std::string t = trim(input);
    t = replaceAll(t, " __ptr64", "");

    while (contains(t, WSTRING_VERBOSE))
        t = replaceAll(t, WSTRING_VERBOSE, "std::wstring");
    while (contains(t, "class std::wstring"))
        t = replaceAll(t, "class std::wstring", "std::wstring");

    // Function pointer: only if standalone (no template <>)
    if (contains(t, "(__cdecl*") && !contains(t, "<"))
        { t = "void *"; if (degraded) *degraded = true; }

    // Unknown templates
    for (const auto& ut : UNKNOWN_TEMPLATES) {
        if (contains(t, ut)) { t = "void *"; if (degraded) *degraded = true; break; }
    }

    // Strip calling conventions
    t = stripWord(t, "__cdecl");
    t = stripWord(t, "__thiscall");

    // 3-level nesting → void* only for complex template types (except std::thread::id)
    // Scope paths like "asw::root::CStr const &" are valid if the namespace/class is defined
    // Only degrade when the 3-level nesting is inside template args (hard to compile)
    if (has3LevelNesting(t) && !contains(t, "std::thread::id") && contains(t, "<"))
        { t = "void *"; if (degraded) *degraded = true; }

    // Remove class/struct prefixes
    t = stripWord(t, "class");
    t = stripWord(t, "struct");

    return collapseSpaces(t);
}

// ============================================================
// Parse comma-separated params respecting template depth
// ============================================================
static std::vector<std::string> parseParamsRaw(const std::string& raw) {
    std::string s = trim(raw);
    if (s.empty() || s == "void") return {};
    std::vector<std::string> params;
    int angleDepth = 0, parenDepth = 0;
    std::string cur;
    for (char c : s) {
        if (c == '<') { angleDepth++; cur += c; }
        else if (c == '>') { angleDepth--; cur += c; }
        else if (c == '(') { parenDepth++; cur += c; }
        else if (c == ')') { parenDepth--; cur += c; }
        else if (c == ',' && angleDepth == 0 && parenDepth == 0) { params.push_back(trim(cur)); cur.clear(); }
        else cur += c;
    }
    if (!trim(cur).empty()) params.push_back(trim(cur));
    return params;
}

// Find top-level '(' — skip template brackets, respect operator< etc.
static int findTopParen(const std::string& s) {
    int d = 0;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (c == '<') {
            // Don't treat < after "operator" as template
            bool isOp = false;
            if (i > 0) {
                size_t j = i;
                while (j > 0 && s[j-1] == ' ') j--;
                if (j >= 8 && s.substr(j-8, 8) == "operator") isOp = true;
                if (j >= 9 && s.substr(j-9, 9) == "operator ") isOp = true;
            }
            if (!isOp) d++;
        }
        else if (c == '>' && d > 0) d--;
        else if (c == '(' && d == 0) return (int)i;
    }
    return -1;
}

static int findMatching(const std::string& s, int start, char oc, char cc) {
    int d = 0;
    for (size_t i = start; i < s.size(); i++) {
        if (s[i] == oc) d++;
        else if (s[i] == cc) { d--; if (d == 0) return (int)i; }
    }
    return -1;
}

// Split by :: respecting template depth
static std::vector<std::string> splitScope(const std::string& s) {
    std::vector<std::string> parts;
    int d = 0;
    std::string cur;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '<') { d++; cur += s[i]; }
        else if (s[i] == '>') { d--; cur += s[i]; }
        else if (s[i] == ':' && i+1 < s.size() && s[i+1] == ':' && d == 0) {
            parts.push_back(cur); cur.clear(); i++; // skip second ':'
        }
        else cur += s[i];
    }
    if (!cur.empty()) parts.push_back(cur);
    return parts;
}

// Extract return type from first scope part (e.g. "int WaCache" → "int", "WaCache")
static std::pair<std::string, std::string> extractReturnType(const std::string& fp_in) {
    std::string fp = trim(fp_in);
    fp = stripWord(fp, "class");
    fp = stripWord(fp, "struct");
    fp = trim(fp);

    // Known return type keywords (longest first)
    const char* kws[] = {
        "unsigned __int64","unsigned long","unsigned int","unsigned char",
        "unsigned short","__int64","wchar_t const *","char const *",
        "void *","void","bool","int","long", nullptr
    };
    for (int i = 0; kws[i]; i++) {
        std::string kw = kws[i];
        if (startsWith(fp, kw + " "))
            return { kw, trim(fp.substr(kw.size())) };
    }

    // enum return
    if (startsWith(fp, "enum ")) {
        size_t sp = fp.rfind(' ');
        if (sp != std::string::npos && sp > 4)
            return { fp.substr(0, sp), trim(fp.substr(sp + 1)) };
    }

    // "TypeName ClassName" — last word starts with uppercase
    size_t sp = fp.rfind(' ');
    if (sp != std::string::npos && sp + 1 < fp.size() && isupper(fp[sp + 1]))
        return { simplifyType(fp.substr(0, sp)), trim(fp.substr(sp + 1)) };

    return { "", fp };
}

// ============================================================
// parse_export: parse one undecorated export name
// ============================================================
static bool parseExport(const std::string& undec, ParsedExport& info) {
    info.original = undec;
    info.kind = "";
    info.access = "";
    info.is_static = false;
    info.is_virtual = false;
    info.is_const = false;
    info.is_free_function = false;
    info.return_type = "";
    info.class_name = "";
    info.method = "";
    info.params_raw = "";

    // vftable/vbtable
    if (contains(undec, "`vftable'") || contains(undec, "`vbtable'")) {
        info.kind = "vftable";
        // Extract class name
        std::regex rx("const (.+)::`v[fb]table'");
        std::smatch m;
        if (std::regex_match(undec, m, rx))
            info.class_name = simplifyType(m[1].str());
        return true;
    }

    // Backtick auto-generated
    if (contains(undec, "`")) {
        info.kind = "auto_generated";
        std::regex rx("(public|protected|private):\\s*(?:virtual\\s+)?(?:void\\s*\\*?\\s*)?(?:__cdecl\\s+)?(.+?)::`");
        std::smatch m;
        if (std::regex_search(undec, m, rx))
            info.class_name = simplifyType(m[2].str());
        return true;
    }

    // MSVC compiler-generated __autoclassinit2 (no backticks, but compiler-internal)
    if (contains(undec, "__autoclassinit2")) {
        info.kind = "auto_generated";
        std::regex rx("(public|protected|private):\\s*(?:static\\s+)?(?:void\\s+)?(?:__cdecl\\s+)?(.+?)::__autoclassinit2");
        std::smatch m;
        if (std::regex_search(undec, m, rx))
            info.class_name = simplifyType(m[2].str());
        return true;
    }

    // Static data members (no parentheses)
    if (!contains(undec, "(")) {
        std::regex rxStatic("(public|protected|private):\\s*static\\s+(.+?)::(\\w+)\\s*$");
        std::smatch m;
        if (std::regex_match(undec, m, rxStatic)) {
            info.kind = "static_data";
            info.access = m[1].str();
            info.is_static = true;
            std::string typeAndClass = trim(m[2].str());
            info.method = m[3].str();

            // Find boundary: last top-level space followed by uppercase
            int lastSpace = -1;
            int depth = 0;
            for (size_t i = 0; i < typeAndClass.size(); i++) {
                if (typeAndClass[i] == '<') depth++;
                else if (typeAndClass[i] == '>') depth--;
                else if (typeAndClass[i] == ' ' && depth == 0) {
                    std::string rest = trim(typeAndClass.substr(i + 1));
                    if (!rest.empty() && isupper(rest[0]))
                        lastSpace = (int)i;
                }
            }
            if (lastSpace >= 0) {
                info.return_type = simplifyType(typeAndClass.substr(0, lastSpace), &info.type_degraded);
                info.class_name = simplifyType(typeAndClass.substr(lastSpace + 1));
            } else {
                auto parts = splitScope(typeAndClass);
                if (parts.size() >= 2) {
                    info.class_name = simplifyType(parts.back());
                    std::string typeStr;
                    for (size_t i = 0; i + 1 < parts.size(); i++) {
                        if (i > 0) typeStr += "::";
                        typeStr += parts[i];
                    }
                    info.return_type = simplifyType(typeStr, &info.type_degraded);
                } else if (parts.size() == 1) {
                    auto [ret, cls] = extractReturnType(parts[0]);
                    info.class_name = cls;
                    info.return_type = ret;
                }
            }
            return true;
        }

        // Pure C name (lowercase identifier, no type info)
        std::regex rxC("^[a-z_]\\w+$");
        if (std::regex_match(undec, rxC)) {
            info.kind = "c_function";
            info.method = undec;
            info.return_type = "void";
            info.params_raw = "void";
            info.class_name = "__c_functions__";
            return true;
        }
        return false; // Can't parse
    }

    // Parse access specifier
    std::string rest;
    std::regex rxAccess("^(public|protected|private):\\s*(.*)");
    std::smatch accM;
    if (std::regex_match(undec, accM, rxAccess)) {
        info.access = accM[1].str();
        rest = accM[2].str();
    } else {
        // No access specifier — check for C function
        std::regex rxCFunc("(.+?)\\s+__cdecl\\s+(\\w+)\\((.+)\\)$");
        std::smatch cm;
        if (std::regex_match(undec, cm, rxCFunc) && !contains(cm[2].str(), "::")) {
            info.kind = "c_function";
            info.method = cm[2].str();
            info.return_type = simplifyType(cm[1].str(), &info.type_degraded);
            info.params_raw = cm[3].str();
            info.class_name = "__c_functions__";
            return true;
        }
        // Namespace-scoped free function (Y-mangling)
        info.access = "public";
        info.is_static = true;
        info.is_free_function = true;
        rest = undec;
    }

    if (startsWith(rest, "static ")) { info.is_static = true; rest = rest.substr(7); }
    if (startsWith(rest, "virtual ")) { info.is_virtual = true; rest = rest.substr(8); }

    int pp = findTopParen(rest);
    if (pp < 0) return false;
    std::string before = trim(rest.substr(0, pp));
    std::string after = rest.substr(pp);
    int pe = findMatching(after, 0, '(', ')');
    if (pe < 0) return false;
    info.params_raw = after.substr(1, pe - 1);
    if (contains(after.substr(pe + 1), "const")) info.is_const = true;

    // Use calling convention as separator between return type and class::method
    std::string retTypeStr;
    std::string scopeMethod;
    size_t ccPos = std::string::npos;
    // Find __cdecl or __thiscall
    for (const char* cc : {"__cdecl", "__thiscall"}) {
        size_t p = before.find(cc);
        if (p != std::string::npos) {
            // Check word boundary
            bool leftOk = (p == 0 || !isalnum(before[p-1]));
            bool rightOk = (p + strlen(cc) >= before.size() || !isalnum(before[p + strlen(cc)]));
            if (leftOk && rightOk) { ccPos = p; break; }
        }
    }

    std::vector<std::string> parts;
    if (ccPos != std::string::npos) {
        retTypeStr = trim(before.substr(0, ccPos));
        size_t afterCC = ccPos;
        // Skip the keyword and trailing spaces
        while (afterCC < before.size() && (isalnum(before[afterCC]) || before[afterCC] == '_')) afterCC++;
        while (afterCC < before.size() && before[afterCC] == ' ') afterCC++;
        scopeMethod = trim(before.substr(afterCC));
        parts = splitScope(scopeMethod);
    } else {
        std::string clean = stripWord(before, "__cdecl");
        clean = stripWord(clean, "__thiscall");
        parts = splitScope(trim(clean));
    }

    if (parts.size() < 2) return false;

    info.method = trim(parts.back());
    std::vector<std::string> classParts(parts.begin(), parts.end() - 1);

    // Destructor
    if (startsWith(info.method, "~")) {
        info.kind = "destructor";
        std::string cp;
        for (size_t i = 0; i < classParts.size(); i++) {
            if (i > 0) cp += "::";
            cp += trim(classParts[i]);
        }
        info.class_name = simplifyType(cp);
        return true;
    }

    // Operator
    if (startsWith(info.method, "operator")) {
        info.kind = "operator_";
        if (!retTypeStr.empty()) {
            info.return_type = simplifyType(retTypeStr, &info.type_degraded);
            std::string cp;
            for (size_t i = 0; i < classParts.size(); i++) { if (i) cp += "::"; cp += trim(classParts[i]); }
            info.class_name = simplifyType(cp);
        } else {
            auto [ret, cls] = extractReturnType(classParts[0]);
            classParts[0] = cls;
            info.return_type = ret;
            std::string cp;
            for (size_t i = 0; i < classParts.size(); i++) { if (i) cp += "::"; cp += trim(classParts[i]); }
            info.class_name = simplifyType(cp);
        }
        return true;
    }

    // Constructor: method name == last class part
    // Only strip leading class/struct (not inside templates like Singleton<class X>)
    std::string lastClean = trim(classParts.back());
    if (startsWith(lastClean, "class ")) lastClean = lastClean.substr(6);
    else if (startsWith(lastClean, "struct ")) lastClean = lastClean.substr(7);
    lastClean = trim(lastClean);
    if (info.method == lastClean) {
        info.kind = "constructor";
        std::string cp;
        for (size_t i = 0; i < classParts.size(); i++) { if (i) cp += "::"; cp += trim(classParts[i]); }
        info.class_name = simplifyType(cp);
        return true;
    }

    // Regular method
    info.kind = "method";
    if (!retTypeStr.empty()) {
        info.return_type = simplifyType(retTypeStr, &info.type_degraded);
        std::string cp;
        for (size_t i = 0; i < classParts.size(); i++) { if (i) cp += "::"; cp += trim(classParts[i]); }
        info.class_name = simplifyType(cp);
    } else {
        auto [ret, cls] = extractReturnType(classParts[0]);
        classParts[0] = cls;
        info.return_type = ret;
        std::string cp;
        for (size_t i = 0; i < classParts.size(); i++) { if (i) cp += "::"; cp += trim(classParts[i]); }
        info.class_name = simplifyType(cp);
    }
    return true;
}

// ============================================================
// Code generation helpers
// ============================================================

static std::string generateParamDecl(const std::string& raw, bool* degraded = nullptr) {
    auto params = parseParamsRaw(raw);
    if (params.empty()) return "";
    std::string r;
    for (size_t i = 0; i < params.size(); i++) {
        if (i > 0) r += ", ";
        std::string simplified = simplifyType(params[i], degraded);
        r += simplified + " p" + std::to_string(i + 1);
    }
    return r;
}

// Check if any parameter or return type would cause mangling mismatch
static void checkParamDegradation(ParsedExport& info) {
    if (info.type_degraded) return;

    // Check params
    for (auto& p : parseParamsRaw(info.params_raw)) {
        bool d = false;
        simplifyType(p, &d);
        if (d) { info.type_degraded = true; return; }
    }

    // Check for types that postprocess() will replace (function pointers in std::function<>)
    // postprocess replaces these with "void *", changing the mangling
    if (contains(info.original, "std::function") && contains(info.original, "(__cdecl*"))
        { info.type_degraded = true; return; }

}

static std::string makeReturnExpr(const std::string& ret) {
    if (ret.empty() || ret == "void") return "";
    if (contains(ret, "*")) return "return nullptr;";
    if (contains(ret, "&"))
        return "static char _buf[4096] = {}; return reinterpret_cast<" + ret + ">(_buf[0]);";
    if (ret == "bool") return "return false;";
    if (ret == "int" || ret == "long" || ret == "unsigned long" || ret == "unsigned int" ||
        ret == "__int64" || ret == "unsigned __int64" || ret == "unsigned char" || ret == "unsigned short")
        return "return 0;";
    return "return {};";
}

static std::string writeDecl(const std::string& clsShort, const ParsedExport& m, bool hasVirt) {
    if (m.kind == "static_data") {
        std::string t = m.return_type.empty() ? "int" : m.return_type;
        return "static " + t + " " + m.method + ";";
    }
    if (m.kind == "constructor")
        return clsShort + "(" + generateParamDecl(m.params_raw) + ");";
    if (m.kind == "destructor") {
        std::string v = (m.is_virtual || hasVirt) ? "virtual " : "";
        return v + "~" + clsShort + "();";
    }
    if (m.kind == "method") {
        std::string s = m.is_static ? "static " : "";
        std::string v = m.is_virtual ? "virtual " : "";
        std::string r = m.return_type.empty() ? "void" : m.return_type;
        std::string c = m.is_const ? " const" : "";
        return s + v + r + " " + m.method + "(" + generateParamDecl(m.params_raw) + ")" + c + ";";
    }
    if (m.kind == "operator_") {
        std::string v = m.is_virtual ? "virtual " : "";
        std::string c = m.is_const ? " const" : "";
        // Conversion operators (operator type()) must NOT have a return type
        bool isConversion = startsWith(m.method, "operator ") &&
                           !contains(m.method, "operator=") && !contains(m.method, "operator==") &&
                           !contains(m.method, "operator!=") && !contains(m.method, "operator<") &&
                           !contains(m.method, "operator>") && !contains(m.method, "operator+") &&
                           !contains(m.method, "operator-") && !contains(m.method, "operator*") &&
                           !contains(m.method, "operator/") && !contains(m.method, "operator[]") &&
                           !contains(m.method, "operator()") && !contains(m.method, "operator&") &&
                           !contains(m.method, "operator|") && !contains(m.method, "operator^") &&
                           !contains(m.method, "operator~") && !contains(m.method, "operator!") &&
                           !contains(m.method, "operator new") && !contains(m.method, "operator delete") &&
                           !contains(m.method, "operator,") && !contains(m.method, "operator%");
        if (isConversion) {
            return v + m.method + "(" + generateParamDecl(m.params_raw) + ")" + c + ";";
        } else {
            std::string r = m.return_type.empty() ? "void" : m.return_type;
            return v + r + " " + m.method + "(" + generateParamDecl(m.params_raw) + ")" + c + ";";
        }
    }
    return "";
}

static std::string writeDef(const std::string& clsFull, const std::string& clsShort, const ParsedExport& m) {
    if (m.kind == "static_data") {
        std::string t = m.return_type.empty() ? "int" : m.return_type;
        return t + " " + clsFull + "::" + m.method + " {};";
    }
    if (m.kind == "constructor")
        return clsFull + "::" + clsShort + "(" + generateParamDecl(m.params_raw) + ") { }";
    if (m.kind == "destructor")
        return clsFull + "::~" + clsShort + "() { }";
    if (m.kind == "method") {
        std::string r = m.return_type.empty() ? "void" : m.return_type;
        std::string c = m.is_const ? " const" : "";
        std::string retExpr = makeReturnExpr(r);
        std::string body = retExpr.empty() ? "{ }" : "{ " + retExpr + " }";
        return r + " " + clsFull + "::" + m.method + "(" + generateParamDecl(m.params_raw) + ")" + c + " " + body;
    }
    if (m.kind == "operator_") {
        std::string c = m.is_const ? " const" : "";
        // Conversion operators: no return type in definition either
        bool isConversion = startsWith(m.method, "operator ") &&
                           !contains(m.method, "operator=") && !contains(m.method, "operator==") &&
                           !contains(m.method, "operator!=") && !contains(m.method, "operator<") &&
                           !contains(m.method, "operator>") && !contains(m.method, "operator+") &&
                           !contains(m.method, "operator-") && !contains(m.method, "operator*") &&
                           !contains(m.method, "operator/") && !contains(m.method, "operator[]") &&
                           !contains(m.method, "operator()") && !contains(m.method, "operator&") &&
                           !contains(m.method, "operator|") && !contains(m.method, "operator^") &&
                           !contains(m.method, "operator~") && !contains(m.method, "operator!") &&
                           !contains(m.method, "operator new") && !contains(m.method, "operator delete") &&
                           !contains(m.method, "operator,") && !contains(m.method, "operator%");
        if (isConversion) {
            return clsFull + "::" + m.method + "(" + generateParamDecl(m.params_raw) + ")" + c + " { return {}; }";
        } else {
            std::string r = m.return_type.empty() ? "void" : m.return_type;
            std::string retExpr = makeReturnExpr(r);
            std::string body = retExpr.empty() ? "{ }" : "{ " + retExpr + " }";
            return r + " " + clsFull + "::" + m.method + "(" + generateParamDecl(m.params_raw) + ")" + c + " " + body;
        }
    }
    return "";
}

// ============================================================
// Topological sort for class definitions
// ============================================================
static std::vector<std::string> topoSort(
    const std::map<std::string, std::vector<ParsedExport>>& classes)
{
    std::set<std::string> classSet;
    for (auto& [k,v] : classes) classSet.insert(k);

    // Build dependency graph
    std::map<std::string, std::set<std::string>> deps;
    for (auto& [cls, methods] : classes) {
        deps[cls] = {};
        for (auto& m : methods) {
            std::string text = m.params_raw + " " + m.return_type;
            for (auto& other : classSet) {
                if (other != cls && contains(text, other))
                    deps[cls].insert(other);
            }
        }
    }

    std::vector<std::string> sorted;
    std::set<std::string> visited;
    std::vector<std::string> remaining;
    for (auto& [k,v] : classes) remaining.push_back(k);

    for (size_t round = 0; round < remaining.size(); round++) {
        bool found = false;
        for (auto& cls : remaining) {
            if (visited.count(cls)) continue;
            bool ready = true;
            for (auto& d : deps[cls]) {
                if (classSet.count(d) && !visited.count(d)) { ready = false; break; }
            }
            if (ready) {
                sorted.push_back(cls);
                visited.insert(cls);
                found = true;
                break;
            }
        }
        if (!found) {
            // Cycle — add remaining
            for (auto& cls : remaining)
                if (!visited.count(cls)) { sorted.push_back(cls); visited.insert(cls); }
            break;
        }
    }
    return sorted;
}

// ============================================================
// Main generator: exports → dllmain3.cpp
// ============================================================
struct GenStats {
    int total = 0, explicit_ = 0, auto_ = 0, ns = 0, pragmaFree = 0, unparseable = 0;
    std::vector<std::string> pragmaNeeded; // decorated names that need pragma fallback
};

static GenStats generate(const std::vector<ExportedFunction>& exports,
                         const std::string& outputFile,
                         const std::string& origDllName) {
    GenStats stats;
    stats.total = (int)exports.size();

    // Parse all exports
    std::vector<ParsedExport> parsedAll;
    std::vector<ExportedFunction> unparseable;
    for (auto& e : exports) {
        ParsedExport info;
        if (parseExport(e.undecoratedName, info)) {
            info.ordinal = e.ordinal;
            info.decorated = e.decoratedName;
            checkParamDegradation(info);
            parsedAll.push_back(info);
        } else {
            unparseable.push_back(e);
        }
    }

    // Group by class
    std::map<std::string, std::vector<ParsedExport>> classes;
    for (auto& info : parsedAll) {
        auto& cls = info.class_name;
        if (cls.empty() || contains(cls, "*") || contains(cls, "&") || contains(cls, " ")) continue;
        classes[cls].push_back(info);
    }

    // Separate Singleton templates
    std::set<std::string> singletonTypes;
    std::vector<ParsedExport> singletonSample;
    std::string sampleClass;
    std::map<std::string, std::vector<ParsedExport>> regular;

    for (auto& [cls, methods] : classes) {
        std::regex rxSingleton("^Singleton<(.+)>$");
        std::smatch sm;
        if (std::regex_match(cls, sm, rxSingleton)) {
            singletonTypes.insert(sm[1].str());
            if (singletonSample.empty()) {
                sampleClass = simplifyType(sm[1].str());
                for (auto& m : methods)
                    if (m.kind != "vftable" && m.kind != "auto_generated")
                        singletonSample.push_back(m);
            }
        } else {
            std::vector<ParsedExport> real;
            for (auto& m : methods)
                if (m.kind != "auto_generated") real.push_back(m);
            if (!real.empty()) regular[cls] = real;
        }
    }

    // Separate namespace groups (including nested namespaces like asw::dll_loader)
    std::map<std::string, std::vector<ParsedExport>> namespaceGroups;
    std::vector<std::string> pragmaFree;
    // Collect names that are STANDALONE struct/class types (not namespace::Type prefixes)
    // "struct MethodInfo" → MethodInfo is a type; "struct WaStringUtils::BlindString" → WaStringUtils is NOT a type
    std::set<std::string> usedAsType;
    for (auto& info : parsedAll) {
        std::regex rx("(?:struct|class)\\s+(\\w+)(?!\\s*::)");
        std::sregex_iterator it(info.original.begin(), info.original.end(), rx), end;
        for (; it != end; ++it) usedAsType.insert((*it)[1].str());
    }

    for (auto it = regular.begin(); it != regular.end(); ) {
        auto& cls = it->first;
        if (cls == "__c_functions__") { ++it; continue; }

        // Check if this name (or its outer scope) conflicts with a struct/class
        bool nameConflict = usedAsType.count(cls) > 0;
        if (!nameConflict && contains(cls, "::")) {
            // For "WaStaticDb::Method", check if "struct WaStaticDb::" appears in exports
            // (meaning WaStaticDb is used as a struct scope, not a namespace)
            std::string outerName = cls.substr(0, cls.find("::"));
            std::regex rxOuter("(?:struct|class)\\s+" + outerName + "\\s*::");
            for (auto& info : parsedAll) {
                if (std::regex_search(info.original, rxOuter)) {
                    nameConflict = true; break;
                }
            }
        }

        auto& methods = it->second;
        std::vector<ParsedExport> real, free, nonFree;
        for (auto& m : methods) {
            if (m.kind == "auto_generated" || m.kind == "vftable") continue;
            real.push_back(m);
            if (m.is_free_function) free.push_back(m);
            else nonFree.push_back(m);
        }
        if (!free.empty() && nonFree.empty() && !nameConflict) {
            // All functions are free, no name conflict → namespace group
            namespaceGroups[cls] = methods;
            it = regular.erase(it);
        } else if (!free.empty() && !nonFree.empty() && !contains(cls, "::")) {
            // Mixed: separate free functions to pragma
            for (auto& m : free) if (!m.decorated.empty()) pragmaFree.push_back(m.decorated);
            std::vector<ParsedExport> kept;
            for (auto& m : methods) if (!m.is_free_function) kept.push_back(m);
            it->second = kept;
            ++it;
        } else ++it;
    }

    // Mark functions as degraded if they reference nested types from namespace function groups
    // e.g. WaStaticDb::Method::param — where WaStaticDb is a namespace group, Method is a class,
    // and param is a nested type that won't be defined until after regular classes.
    {
        std::set<std::string> nsFuncPrefixes;
        for (auto& [ns, _] : namespaceGroups) nsFuncPrefixes.insert(ns);
        for (auto& [cls, methods] : regular) {
            for (auto& m : methods) {
                if (m.type_degraded) continue;
                // Check for "struct/class/enum NsFunc::Class::NestedType" in original
                std::regex rxNested("(?:struct|class|enum)\\s+(\\w+)::(\\w+)::(\\w+)");
                std::sregex_iterator it(m.original.begin(), m.original.end(), rxNested), end;
                for (; it != end; ++it) {
                    if (nsFuncPrefixes.count((*it)[1].str())) {
                        m.type_degraded = true;
                        break;
                    }
                }
            }
        }
    }

    // Split top-level vs nested
    std::map<std::string, std::vector<ParsedExport>> topRegular, nestedRegular;
    for (auto& [cls, methods] : regular) {
        if (contains(cls, "::")) nestedRegular[cls] = methods;
        else topRegular[cls] = methods;
    }

    auto sortedClasses = topoSort(topRegular);

    // Collect class names
    std::set<std::string> nsNames;
    for (auto& [k,v] : namespaceGroups) nsNames.insert(k);
    std::set<std::string> allClassNames;
    for (auto& [k,v] : topRegular) {
        std::regex rxValid("^[A-Za-z]\\w*$");
        if (std::regex_match(k, rxValid) && !nsNames.count(k))
            allClassNames.insert(k);
    }
    for (auto& t : singletonTypes) {
        std::regex rxValid("^[A-Za-z]\\w*$");
        if (std::regex_match(t, rxValid) && !nsNames.count(t))
            allClassNames.insert(t);
    }

    // Collect nested enums
    std::map<std::string, std::set<std::string>> classEnums;
    for (auto& info : parsedAll) {
        std::regex rx("enum (\\w+)::(\\w+)");
        std::sregex_iterator it(info.original.begin(), info.original.end(), rx), end;
        for (; it != end; ++it) classEnums[(*it)[1].str()].insert((*it)[2].str());
    }

    // Collect nested structs/classes with correct keyword
    std::map<std::string, std::map<std::string, std::string>> classStructs; // parent -> {name -> "class"|"struct"}
    for (auto& info : parsedAll) {
        std::regex rx("(struct|class) (\\w+)::(\\w+)");
        std::sregex_iterator it(info.original.begin(), info.original.end(), rx), end;
        for (; it != end; ++it) {
            std::string kind = (*it)[1].str(), parent = (*it)[2].str(), sname = (*it)[3].str();
            if (!sname.empty() && isupper(sname[0]) && allClassNames.count(parent)) {
                if (nestedRegular.count(parent + "::" + sname)) continue;
                if (!classStructs[parent].count(sname) || kind == "class")
                    classStructs[parent][sname] = kind;
            }
        }
    }

    // Struct stubs (must come before standalone enums so structTypes is available)
    std::set<std::string> manually = {"IWaAsyncIO"};
    // Collect namespace prefixes to exclude from structTypes (e.g. "asw", "root" from "asw::root::CGenericFile")
    std::set<std::string> nsPrefixes;
    for (auto& [cls, _] : nestedRegular) {
        auto parts = splitScope(cls);
        for (size_t i = 0; i + 1 < parts.size(); i++) nsPrefixes.insert(parts[i]);
    }
    for (auto& [ns, _] : namespaceGroups) {
        auto parts = splitScope(ns);
        for (auto& p : parts) nsPrefixes.insert(p);
    }

    std::set<std::string> structTypes;
    for (auto& info : parsedAll) {
        std::regex rx("struct (\\w+)");
        std::sregex_iterator it(info.original.begin(), info.original.end(), rx), end;
        for (; it != end; ++it) {
            std::string s = (*it)[1].str();
            if (!SDK_STRUCTS.count(s) && !allClassNames.count(s) && s != "std"
                && !nsNames.count(s) && !manually.count(s) && !nsPrefixes.count(s))
                structTypes.insert(s);
        }
    }

    // Standalone enums (skip scoped enums like "enum ClassName::EnumName")
    std::set<std::string> standaloneEnums;
    for (auto& info : parsedAll) {
        std::regex rx("enum ([A-Z]\\w+)");
        std::sregex_iterator it(info.original.begin(), info.original.end(), rx), end;
        for (; it != end; ++it) {
            std::string e = (*it)[1].str();
            size_t pos = (*it).position();
            size_t afterPos = pos + 5 + e.size();
            if (afterPos + 1 < info.original.size() &&
                info.original[afterPos] == ':' && info.original[afterPos+1] == ':')
                continue;
            bool isNested = false;
            for (auto& [p, v] : classEnums) if (v.count(e)) { isNested = true; break; }
            if (!isNested && !allClassNames.count(e) && !nsNames.count(e)
                && !structTypes.count(e) && !topRegular.count(e))
                standaloneEnums.insert(e);
        }
    }

    // Build set of class names that will be generated with __declspec(dllexport)
    std::set<std::string> generatedClassNames;
    for (auto& [cls, _] : topRegular) generatedClassNames.insert(cls);
    for (auto& [cls, _] : nestedRegular) {
        size_t pos = cls.find("::");
        if (pos == std::string::npos) continue;
        std::string outer = cls.substr(0, pos);
        std::string rest = cls.substr(pos + 2);

        // Case 1: nested class inside a generated top-level class (single-level nesting)
        if (topRegular.count(outer) && rest.find("::") == std::string::npos) {
            generatedClassNames.insert(cls);
            continue;
        }

        // Case 2: class under namespace prefix (e.g. asw::root::CGenericFile)
        // Will be generated as namespace { class { } } if outer is NOT a top-level class
        size_t lastSep = cls.rfind("::");
        std::string nsPrefix = cls.substr(0, lastSep);
        auto prefixParts = splitScope(nsPrefix);
        bool outerIsClass = (prefixParts.size() == 1 && topRegular.count(prefixParts[0]));
        if (!outerIsClass) {
            generatedClassNames.insert(cls);
        }
    }
    for (auto& t : singletonTypes) generatedClassNames.insert("Singleton<" + t + ">");
    for (auto& [cls, _] : namespaceGroups) generatedClassNames.insert(cls);
    generatedClassNames.insert("__c_functions__");

    // Build set of pragmaFree decorated names (already handled separately)
    std::set<std::string> pragmaFreeSet(pragmaFree.begin(), pragmaFree.end());

    // Determine which exports need pragma (precise detection)
    for (auto& info : parsedAll) {
        if (info.decorated.empty()) continue;
        if (pragmaFreeSet.count(info.decorated)) continue; // already handled

        bool needPragma = false;
        if (info.kind == "auto_generated") {
            // Auto-generated exports (default ctor closure, scalar deleting dtor, etc.)
            // are unreliable — compiler may or may not generate them. Always pragma.
            needPragma = true;
        } else if (info.kind == "vftable") {
            // vftable is reliably generated by __declspec(dllexport) if class exists
            needPragma = !generatedClassNames.count(info.class_name);
        } else if (info.kind == "static_data") {
            // Static data: type parsing from UnDecorateSymbolName can be imprecise
            // (e.g. extra const on pointer: "const * const" vs "const *").
            // Use pragma for pointer/reference types where const precision matters.
            needPragma = !generatedClassNames.count(info.class_name) ||
                         info.type_degraded ||
                         contains(info.return_type, "*") ||
                         contains(info.return_type, "&");
        } else {
            // Method/ctor/dtor/operator/c_function:
            // needs pragma if class not generated OR type was degraded
            needPragma = !generatedClassNames.count(info.class_name) || info.type_degraded;
        }
        if (needPragma) stats.pragmaNeeded.push_back(info.decorated);
    }

    // Count
    for (auto& info : parsedAll) {
        if (info.kind == "auto_generated" || info.kind == "vftable") stats.auto_++;
        else stats.explicit_++;
    }
    stats.ns = (int)namespaceGroups.size();
    stats.pragmaFree = (int)pragmaFree.size();
    stats.unparseable = (int)unparseable.size();

    // ========== Write output ==========
    std::ofstream f(outputFile);

    f << "#include <windows.h>\n#include <string>\n#include <vector>\n";
    f << "#include <map>\n#include <set>\n#include <unordered_map>\n";
    f << "#include <memory>\n#include <functional>\n#include <mutex>\n";
    f << "#include <atomic>\n#include <list>\n#include <utility>\n";
    f << "#include <thread>\n#include <array>\n#include <shared_mutex>\n";
    f << "#include <comdef.h>\n#include <Wbemidl.h>\n";
    f << "#pragma comment(lib, \"user32.lib\")\n";
    f << "#pragma comment(lib, \"wbemuuid.lib\")\n\n";
    f << "// Total: " << stats.total << " | C++: " << stats.explicit_
      << " | Auto: " << stats.auto_ << " | NS: " << stats.ns
      << " | Pragma: " << stats.pragmaNeeded.size()
      << " | Unparseable: " << stats.unparseable << "\n\n";

    // Stubs
    f << "namespace ATL {\n    template<typename T> class CComPtr {\n"
      << "        T* p;\n    public:\n        CComPtr() : p(nullptr) {}\n"
      << "        CComPtr(const CComPtr&) : p(nullptr) {}\n"
      << "        CComPtr& operator=(const CComPtr&) { return *this; }\n    };\n}\n\n";
    f << "struct IWaAsyncIO { virtual ~IWaAsyncIO() {} };\n";
    f << "template<typename T1, typename T2> class WaAsyncIO : public IWaAsyncIO {};\n\n";
    f << "template<typename T> class wa_allocator : public std::allocator<T> {\npublic: using std::allocator<T>::allocator;\n};\n";
    f << "struct wa_map_hasher {\n    size_t operator()(const std::wstring& k) const { return std::hash<std::wstring>{}(k); }\n};\n";
    f << "struct wa_map_equal_to {\n    bool operator()(const std::wstring& a, const std::wstring& b) const { return a == b; }\n};\n\n";

    for (auto& e : standaloneEnums) f << "enum " << e << " { " << e << "_Default = 0 };\n";
    if (!standaloneEnums.empty()) f << "\n";
    for (auto& s : structTypes) f << "struct " << s << " {};\n";
    if (!structTypes.empty()) f << "\n";

    f << "// Forward declarations\n";
    for (auto& cls : allClassNames) f << "class " << cls << ";\n";
    for (auto& extra : EXTRA_FORWARD_DECLS) f << extra << ";\n";
    f << "\n";

    // Singleton template
    if (!singletonTypes.empty() && !singletonSample.empty()) {
        f << "// ============ Singleton Template ============\n\n";
        bool hasVirt = false;
        auto firstSingleton = "Singleton<" + *singletonTypes.begin() + ">";
        if (classes.count(firstSingleton))
            for (auto& m : classes[firstSingleton]) if (m.kind == "vftable") hasVirt = true;

        f << "template<typename T>\nclass Singleton {\n";
        std::map<std::string, std::vector<ParsedExport>> byAcc;
        for (auto& m : singletonSample) {
            if (m.kind == "vftable" || m.kind == "auto_generated") continue;
            std::string acc = m.access.empty() ? "public" : m.access;
            byAcc[acc].push_back(m);
        }
        for (auto& acc : {"public", "protected", "private"}) {
            if (!byAcc.count(acc) || byAcc[acc].empty()) continue;
            f << acc << ":\n";
            for (auto& m : byAcc[acc]) {
                ParsedExport mt = m;
                if (!sampleClass.empty() && !mt.return_type.empty())
                    mt.return_type = replaceAll(mt.return_type, sampleClass, "T");
                f << "    " << writeDecl("Singleton", mt, hasVirt) << "\n";
            }
        }
        f << "};\n\n";
        for (auto& m : singletonSample) {
            if (m.kind == "vftable" || m.kind == "auto_generated") continue;
            ParsedExport mt = m;
            if (!sampleClass.empty() && !mt.return_type.empty())
                mt.return_type = replaceAll(mt.return_type, sampleClass, "T");
            f << "template<typename T>\n" << writeDef("Singleton<T>", "Singleton", mt) << "\n";
        }
        f << "\n";
        for (auto& t : singletonTypes)
            f << "template class __declspec(dllexport) Singleton<" << t << ">;\n";
        f << "\n";
    }

    // Regular classes (buffered — emitted after namespace classes to resolve forward references)
    std::ostringstream regularBuf;
    for (auto& clsName : sortedClasses) {
        if (!topRegular.count(clsName)) continue;
        auto& methods = topRegular[clsName];
        bool hasVirt = false;
        for (auto& m : methods) if (m.kind == "vftable") hasVirt = true;

        // Find nested classes
        std::map<std::string, std::vector<ParsedExport>> nested;
        for (auto& [other, nm] : nestedRegular) {
            if (startsWith(other, clsName + "::") &&
                std::count(other.begin(), other.end(), ':') == 2) {
                nested[other.substr(clsName.size() + 2)] = nm;
            }
        }

        regularBuf << "// " << std::string(60, '-') << "\n";
        regularBuf << "class __declspec(dllexport) " << clsName;
        if (singletonTypes.count(clsName))
            regularBuf << " : public Singleton<" << clsName << ">";
        regularBuf << " {\n";

        // Nested enums
        if (classEnums.count(clsName)) {
            regularBuf << "public:\n";
            for (auto& e : classEnums[clsName])
                regularBuf << "    enum " << e << " { " << e << "_Default = 0 };\n";
        }
        // Nested structs/classes
        if (classStructs.count(clsName)) {
            regularBuf << "public:\n";
            for (auto& [s, kind] : classStructs[clsName])
                regularBuf << "    " << kind << " " << s << " {};\n";
        }
        // Nested classes with members
        for (auto& [nc, ncm] : nested) {
            bool ncVirt = false;
            for (auto& m : ncm) if (m.kind == "vftable") ncVirt = true;
            regularBuf << "public:\n    class __declspec(dllexport) " << nc << " {\n";
            std::map<std::string, std::vector<ParsedExport>> ncByAcc;
            for (auto& m : ncm) {
                if (m.kind == "vftable" || m.kind == "auto_generated") continue;
                std::string acc = m.access.empty() ? "public" : m.access;
                ncByAcc[acc].push_back(m);
            }
            for (auto& acc : {"public", "protected", "private"}) {
                if (!ncByAcc.count(acc) || ncByAcc[acc].empty()) continue;
                regularBuf << "    " << acc << ":\n";
                for (auto& m : ncByAcc[acc])
                    regularBuf << "        " << writeDecl(nc, m, ncVirt) << "\n";
            }
            regularBuf << "    };\n";
        }

        // Main class members by access
        std::map<std::string, std::vector<ParsedExport>> byAcc;
        for (auto& m : methods) {
            if (m.kind == "vftable" || m.kind == "auto_generated") continue;
            std::string acc = m.access.empty() ? "public" : m.access;
            byAcc[acc].push_back(m);
        }
        std::set<std::string> seenDecls;
        for (auto& acc : {"public", "protected", "private"}) {
            if (!byAcc.count(acc) || byAcc[acc].empty()) continue;
            regularBuf << acc << ":\n";
            for (auto& m : byAcc[acc]) {
                std::string decl = writeDecl(clsName, m, hasVirt);
                if (seenDecls.insert(decl).second)
                    regularBuf << "    " << decl << "\n";
            }
        }
        regularBuf << "};\n\n";

        // Out-of-class definitions
        std::set<std::string> seenDefs;
        for (auto& m : methods) {
            if (m.kind == "vftable" || m.kind == "auto_generated") continue;
            std::string def = writeDef(clsName, clsName, m);
            if (seenDefs.insert(def).second)
                regularBuf << def << "\n";
        }
        for (auto& [nc, ncm] : nested) {
            for (auto& m : ncm) {
                if (m.kind == "vftable" || m.kind == "auto_generated") continue;
                std::string def = writeDef(clsName + "::" + nc, nc, m);
                if (seenDefs.insert(def).second)
                    regularBuf << def << "\n";
            }
        }
        regularBuf << "\n";
    }

    // Namespaced classes: nested classes whose outer scope is NOT a generated class
    // (e.g. asw::root::CGenericFile where "asw" is a namespace, not a class)
    {
        // Group nestedRegular entries by their namespace prefix
        // e.g. "asw::root::CGenericFile" → prefix "asw::root", class "CGenericFile"
        std::map<std::string, std::map<std::string, std::vector<ParsedExport>>> nsClasses;
        for (auto& [fullName, methods] : nestedRegular) {
            size_t lastSep = fullName.rfind("::");
            if (lastSep == std::string::npos) continue;
            std::string nsPrefix = fullName.substr(0, lastSep);
            std::string clsShort = fullName.substr(lastSep + 2);

            // Skip if the outer class IS in topRegular (handled by regular class nesting)
            // Only handle cases where the prefix is a namespace (not a class)
            auto prefixParts = splitScope(nsPrefix);
            bool outerIsClass = false;
            if (prefixParts.size() == 1 && topRegular.count(prefixParts[0])) outerIsClass = true;
            if (outerIsClass) continue;

            nsClasses[nsPrefix][clsShort] = methods;
        }

        if (!nsClasses.empty()) {
            f << "// ============ Namespaced classes ============\n\n";
            for (auto& [nsPrefix, clsMap] : nsClasses) {
                auto nsParts = splitScope(nsPrefix);
                std::string indent;
                for (auto& part : nsParts) {
                    f << indent << "namespace " << part << " {\n";
                    indent += "    ";
                }

                // Forward declarations for all classes in this namespace
                for (auto& [cls, _] : clsMap)
                    f << indent << "class " << cls << ";\n";

                // Collect and declare nested types (enums, structs) referenced by methods
                std::set<std::string> nsStructs, nsEnums;
                for (auto& [cls, methods] : clsMap) {
                    for (auto& m : methods) {
                        // Find struct/class/enum types scoped to this namespace
                        // Use full nsPrefix (e.g. "asw::root") not just innermost part
                        std::regex rxS("(?:struct|class)\\s+" + nsPrefix + "::(\\w+)");
                        std::regex rxE("enum\\s+" + nsPrefix + "::(\\w+)");
                        std::sregex_iterator it(m.original.begin(), m.original.end(), rxS), end;
                        for (; it != end; ++it) {
                            std::string s = (*it)[1].str();
                            if (!clsMap.count(s) && !SDK_STRUCTS.count(s)) nsStructs.insert(s);
                        }
                        std::sregex_iterator it2(m.original.begin(), m.original.end(), rxE), end2;
                        for (; it2 != end2; ++it2) nsEnums.insert((*it2)[1].str());
                    }
                }
                for (auto& e : nsEnums) f << indent << "enum " << e << " { " << e << "_Default = 0 };\n";
                for (auto& s : nsStructs) f << indent << "struct " << s << " {};\n";
                f << "\n";

                // Strip namespace prefix from param types (we're inside the namespace)
                std::string nsPrefixColons = nsPrefix + "::";

                for (auto& [clsShort, methods] : clsMap) {
                    std::string fullName = nsPrefix + "::" + clsShort;
                    bool hasVirt = false;
                    for (auto& m : methods) if (m.kind == "vftable") hasVirt = true;

                    // Detect nested struct/enum types inside this class
                    // Scan ALL exports (not just this class's methods) since nested types
                    // may be referenced by other classes (e.g. WaValidator uses WaStaticDb::Method::param)
                    std::string fullClsPrefix = fullName + "::";
                    std::set<std::string> clsNestedStructs, clsNestedEnums;
                    std::regex rxNS("(?:struct|class)\\s+" + fullClsPrefix + "(\\w+)");
                    std::regex rxNE("enum\\s+" + fullClsPrefix + "(\\w+)");
                    for (auto& info : parsedAll) {
                        std::sregex_iterator it(info.original.begin(), info.original.end(), rxNS), end;
                        for (; it != end; ++it) clsNestedStructs.insert((*it)[1].str());
                        std::sregex_iterator it2(info.original.begin(), info.original.end(), rxNE), end2;
                        for (; it2 != end2; ++it2) clsNestedEnums.insert((*it2)[1].str());
                    }

                    // Strip namespace prefix AND self-qualified class name from params/return types
                    std::string clsShortColons = clsShort + "::";
                    // localMethods: strip namespace + self-qualified names (for declarations inside class)
                    std::vector<ParsedExport> localMethods;
                    for (auto& m : methods) {
                        ParsedExport lm = m;
                        lm.params_raw = replaceAll(lm.params_raw, nsPrefixColons, "");
                        lm.params_raw = replaceAll(lm.params_raw, clsShortColons, "");
                        lm.return_type = replaceAll(lm.return_type, nsPrefixColons, "");
                        lm.return_type = replaceAll(lm.return_type, clsShortColons, "");
                        localMethods.push_back(lm);
                    }
                    // defMethods: strip only namespace prefix (for out-of-class definitions)
                    std::vector<ParsedExport> defMethods;
                    for (auto& m : methods) {
                        ParsedExport dm = m;
                        dm.params_raw = replaceAll(dm.params_raw, nsPrefixColons, "");
                        dm.return_type = replaceAll(dm.return_type, nsPrefixColons, "");
                        defMethods.push_back(dm);
                    }

                    f << indent << "class __declspec(dllexport) " << clsShort << " {\n";
                    // Emit nested types
                    if (!clsNestedEnums.empty() || !clsNestedStructs.empty()) {
                        f << indent << "public:\n";
                        for (auto& e : clsNestedEnums) f << indent << "    enum " << e << " { " << e << "_Default = 0 };\n";
                        for (auto& s : clsNestedStructs) f << indent << "    struct " << s << " {};\n";
                    }

                    std::map<std::string, std::vector<ParsedExport>> byAcc;
                    for (auto& m : localMethods) {
                        if (m.kind == "vftable" || m.kind == "auto_generated") continue;
                        std::string acc = m.access.empty() ? "public" : m.access;
                        byAcc[acc].push_back(m);
                    }
                    std::set<std::string> seenDecls;
                    for (auto& acc : {"public", "protected", "private"}) {
                        if (!byAcc.count(acc) || byAcc[acc].empty()) continue;
                        f << indent << acc << ":\n";
                        for (auto& m : byAcc[acc]) {
                            std::string decl = writeDecl(clsShort, m, hasVirt);
                            if (seenDecls.insert(decl).second)
                                f << indent << "    " << decl << "\n";
                        }
                    }
                    f << indent << "};\n\n";

                    // Out-of-class definitions (use defMethods which keeps class-qualified return types)
                    std::set<std::string> seenDefs;
                    for (auto& m : defMethods) {
                        if (m.kind == "vftable" || m.kind == "auto_generated") continue;
                        std::string def = writeDef(clsShort, clsShort, m);
                        if (seenDefs.insert(def).second)
                            f << indent << def << "\n";
                    }
                    f << "\n";

                    // Track as generated
                    generatedClassNames.insert(fullName);
                }

                for (size_t i = nsParts.size(); i > 0; i--)
                    f << std::string((i - 1) * 4, ' ') << "}\n";
                f << "\n";
            }
        }
    }

    // Now emit buffered regular classes (after namespace classes so forward references resolve)
    f << regularBuf.str();

    // Namespace functions
    if (!namespaceGroups.empty()) {
        f << "// ============ Namespace functions ============\n\n";
        for (auto& [nsName, methods] : namespaceGroups) {
            // Handle nested namespaces (e.g. "asw::dll_loader" → namespace asw { namespace dll_loader { ... }})
            auto nsParts = splitScope(nsName);
            std::string indent;
            for (auto& part : nsParts) {
                f << indent << "namespace " << part << " {\n";
                indent += "    ";
            }

            // Detect nested types
            std::set<std::string> nsTypes, nsEnums;
            // Use full namespace name for type detection
            std::regex rxT("(?:struct|class)\\s+" + nsName + "::(\\w+)");
            std::regex rxE("enum\\s+" + nsName + "::(\\w+)");
            for (auto& m : methods) {
                std::sregex_iterator it(m.original.begin(), m.original.end(), rxT), end;
                for (; it != end; ++it) nsTypes.insert((*it)[1].str());
                std::sregex_iterator it2(m.original.begin(), m.original.end(), rxE), end2;
                for (; it2 != end2; ++it2) nsEnums.insert((*it2)[1].str());
            }
            for (auto& e : nsEnums) f << indent << "enum " << e << " { " << e << "_Default = 0 };\n";
            for (auto& t : nsTypes) f << indent << "template<typename T=void> struct " << t << " {};\n";

            for (auto& m : methods) {
                if (m.kind == "auto_generated" || m.kind == "vftable") continue;
                std::string r = m.return_type.empty() ? "void" : m.return_type;
                std::string params = generateParamDecl(m.params_raw);
                std::string c = m.is_const ? " const" : "";
                std::string retExpr = makeReturnExpr(r);
                std::string body = retExpr.empty() ? "{ }" : "{ " + retExpr + " }";
                f << indent << "__declspec(dllexport) " << r << " __cdecl " << m.method
                  << "(" << params << ")" << c << " " << body << "\n";
            }

            // Close all namespace braces
            for (size_t i = nsParts.size(); i > 0; i--)
                f << std::string((i - 1) * 4, ' ') << "}\n";
            f << "\n";
        }
    }

    // Pragma for mixed class/namespace
    if (!pragmaFree.empty()) {
        for (auto& dec : pragmaFree)
            f << "#pragma comment(linker, \"/export:" << dec << "=" << origDllName << "." << dec << "\")\n";
        f << "\n";
    }

    // C functions
    if (classes.count("__c_functions__")) {
        f << "// ============ C-linkage functions ============\n\n";
        for (auto& m : classes["__c_functions__"]) {
            if (m.kind != "c_function") continue;
            std::string r = m.return_type.empty() ? "void" : m.return_type;
            std::string params = generateParamDecl(m.params_raw);
            std::string retExpr = makeReturnExpr(r);
            std::string body = retExpr.empty() ? "{ }" : "{ " + retExpr + " }";
            f << "extern \"C\" __declspec(dllexport) " << r << " __cdecl "
              << m.method << "(" << params << ") " << body << "\n";
        }
        f << "\n";
    }

    // Unparseable → pragma
    if (!unparseable.empty()) {
        for (auto& e : unparseable) {
            if (!e.decoratedName.empty())
                f << "#pragma comment(linker, \"/export:" << e.decoratedName
                  << "=" << origDllName << "." << e.decoratedName << "\")\n";
        }
        f << "\n";
    }

    // ============ Precise pragma: only mismatched exports ============
    if (!stats.pragmaNeeded.empty()) {
        f << "\n// ============ Pragma fixup: " << stats.pragmaNeeded.size()
          << " exports with mangling mismatch ============\n";
        f << "// These exports cannot be matched by C++ class reconstruction alone.\n";
        f << "// Compile with: cl /LD /W0 /std:c++17 ... /link /IGNORE:4197\n\n";
        for (auto& dec : stats.pragmaNeeded) {
            f << "#pragma comment(linker, \"/export:" << dec
              << "=" << origDllName << "." << dec << "\")\n";
        }
        f << "\n";
    }

    // Payload & DllMain
    f << "\n// ============ Payload & DllMain ============\n\n";
    f << "void Payload() {\n";
    f << "    MessageBoxA(NULL, \"DLL Proxy Loaded (Method 3)\", \"ZeroEye\", MB_OK);\n}\n\n";
    f << "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n";
    f << "    switch (ul_reason_for_call) {\n";
    f << "    case DLL_PROCESS_ATTACH:\n        DisableThreadLibraryCalls(hModule);\n        Payload();\n        break;\n";
    f << "    case DLL_PROCESS_DETACH:\n        break;\n    }\n    return TRUE;\n}\n";
    f.close();

    return stats;
}

// ============================================================
// Post-processing: fix compilation issues
// ============================================================
static void postprocess(const std::string& cppFile) {
    std::ifstream in(cppFile);
    std::string code((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    code = replaceAll(code, "struct BlindString {};", "template<typename T> struct BlindString {};");
    code = replaceAll(code, "struct WaDbgCallTracker {};",
                      "struct WaDbgCallTracker { template<typename T> struct Scope {}; };");

    if (contains(code, "namespace WaStringUtils"))
        code = replaceAll(code, "// Forward declarations\n",
                          "// Forward declarations\nnamespace WaStringUtils { template<typename T> struct BlindString {}; }\n");

    // Move WaHttpLowLevel before WaHttp if needed
    {
        std::string llMarker = "class __declspec(dllexport) WaHttpLowLevel {";
        std::string hMarker = "class __declspec(dllexport) WaHttp {";
        size_t llPos = code.find(llMarker);
        size_t hPos = code.find(hMarker);
        if (llPos != std::string::npos && hPos != std::string::npos && llPos > hPos) {
            // Find the block boundaries for WaHttpLowLevel
            size_t blockStart = code.rfind("// " + std::string(60, '-'), llPos);
            size_t blockEnd = llPos;
            // Find the end of the class block (next "// ---" section)
            size_t nextSection = code.find("// " + std::string(60, '-'), llPos + 10);
            if (blockStart != std::string::npos && nextSection != std::string::npos) {
                std::string block = code.substr(blockStart, nextSection - blockStart);
                code.erase(blockStart, nextSection - blockStart);
                // Re-find WaHttp position after erase
                size_t insertPos = code.find("// " + std::string(60, '-') + "\nclass __declspec(dllexport) WaHttp ");
                if (insertPos != std::string::npos)
                    code.insert(insertPos, block);
            }
        }
    }

    // Clean broken static data members (line-by-line)
    {
        std::istringstream iss(code);
        std::string line, cleaned;
        while (std::getline(iss, line)) {
            std::string trimmed = trim(line);
            if (startsWith(trimmed, "std recursive_mutex") ||
                startsWith(trimmed, "std atomic") ||
                startsWith(trimmed, "static std recursive_mutex") ||
                startsWith(trimmed, "static std atomic"))
                continue; // skip broken line
            cleaned += line + "\n";
        }
        code = cleaned;
    }

    // Fix function pointer in std::function template args
    std::regex rxFP("std::function<int \\(void \\(\\*\\)\\(wchar_t \\*\\),std::shared_ptr<WaSignalLock>,int,WaJson\\)>");
    code = std::regex_replace(code, rxFP, "void *");

    std::ofstream out(cppFile);
    out << code;
    out.close();
}

// (No compile/link dependencies — all pragma fallback is determined statically)

} // namespace ProxyGen
