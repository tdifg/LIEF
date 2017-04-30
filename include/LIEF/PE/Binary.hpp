/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_PE_BINARY_H_
#define LIEF_PE_BINARY_H_

#include <map>

#include "LIEF/PE/Structures.hpp"
#include "LIEF/PE/Header.hpp"
#include "LIEF/PE/OptionalHeader.hpp"
#include "LIEF/PE/DosHeader.hpp"
#include "LIEF/PE/Section.hpp"
#include "LIEF/PE/Import.hpp"
#include "LIEF/PE/DataDirectory.hpp"
#include "LIEF/PE/TLS.hpp"
#include "LIEF/PE/Symbol.hpp"
#include "LIEF/PE/utils.hpp"
#include "LIEF/PE/Relocation.hpp"
#include "LIEF/PE/ResourceDirectory.hpp"
#include "LIEF/PE/Export.hpp"
#include "LIEF/PE/Debug.hpp"
#include "LIEF/PE/ResourcesManager.hpp"
#include "LIEF/PE/signature/Signature.hpp"

#include "LIEF/Abstract/Binary.hpp"

#include "LIEF/visibility.h"

namespace LIEF {
namespace PE {
class Parser;
class Builder;

//! @brief Class which represent a PE binary object
class DLL_PUBLIC Binary : public LIEF::Binary {
  friend class Parser;
  friend class Builder;

  public:
    Binary(const std::string& name, PE_TYPE type);

    virtual ~Binary(void);

    //! @brief Return `PE32` or `PE32+`
    PE_TYPE type(void) const;

    //! @brief Convert Relative Virtual Address to offset
    //!
    //! We try to get the get section wich hold the given
    //! `RVA` and convert it to offset. If the section
    //! does not exist, we assume that `RVA` = `offset`
    uint64_t rva_to_offset(uint64_t RVA);

    //! @brief Convert Virtual address to offset
    uint64_t va_to_offset(uint64_t VA);

    //! @brief Find the section associated with the `offset`
    Section&       section_from_offset(uint64_t offset);
    const Section& section_from_offset(uint64_t offset) const;

    //! @brief Find the section associated with the `virtual address`
    Section&       section_from_virtual_address(uint64_t virtual_address);
    const Section& section_from_virtual_address(uint64_t virtual_address) const;

    //! @brief Return binary's sections
    it_sections       get_sections(void);
    it_const_sections get_sections(void) const;

    // =======
    // Headers
    // =======

    //! @brief Return a reference to the PE::DosHeader object
    DosHeader&       dos_header(void);
    const DosHeader& dos_header(void) const;

    //! @brief Return a reference to the PE::Header object
    Header&       header(void);
    const Header& header(void) const;

    //! @brief Return a reference to the OptionalHeader object
    OptionalHeader&       optional_header(void);
    const OptionalHeader& optional_header(void) const;

    //! @brief Compute the binary's virtual size.
    //! It should match with OptionalHeader::sizeof_image
    uint64_t get_virtual_size(void) const;

    //! @brief Compute the size of all headers
    uint32_t get_sizeof_headers(void) const;


    //! @brief Return a reference to the TLS object
    TLS&       tls(void);
    const TLS& tls(void) const;

    //! @brief Set a TLS object in the current Binary
    void tls(const TLS& tls);

    //! @brief Check if the current binary has a TLS object
    bool has_tls(void) const;

    //! @brief Check if the current binary has imports
    //!
    //! @see Import
    bool has_imports(void) const;

    //! @brief Check if the current binary is signed
    bool has_signature(void) const;

    //! @brief Check if the current binary has exports.
    //!
    //! @see Export
    bool has_exports(void) const;

    //! @brief Check if the current binary has resources
    bool has_resources(void) const;

    //! @brief Check if the current binary has exceptions
    bool has_exceptions(void) const;

    //! @brief Check if the current binary has relocations
    //!
    //! @see Relocation
    bool has_relocations(void) const;

    //! @brief Check if the current binary has debugs
    bool has_debug(void) const;

    //! @brief Check if the current binary has configuration
    bool has_configuration(void) const;

    //! @brief Return the Signature object if the bianry is signed
    const Signature& signature(void) const;

    //! @brief Try to predict the RVA of the function `function` in the import library `library`
    //!
    //! @warning
    //! The value could be changed if imports change
    uint32_t predict_function_rva(const std::string& library, const std::string& function);

    //! @brief Return a Export object
    Export&       get_export(void);
    const Export& get_export(void) const;

    //!@brief Return binary's Symbol
    std::vector<Symbol>&       symbols(void);
    const std::vector<Symbol>& symbols(void) const;

    ResourceNode&                  get_resources(void);
    const ResourceNode&            get_resources(void) const;
    void set_resources(ResourceNode* resource);
    ResourcesManager               get_resources_manager(void);
    const ResourcesManager         get_resources_manager(void) const;

    // ==========================
    // Methods to manage sections
    // ==========================

    //! @brief Return binary's section from its name
    //!
    //! @param[in] name Name of the Section
    Section&       get_section(const std::string& name);
    const Section& get_section(const std::string& name) const;

    //! @brief Return the section associated with import table
    const Section& get_import_section(void) const;
    Section&       get_import_section(void);

    //! @brief Delete the section with the given name
    //!
    //! @param[in] name Name of section to delete
    void  delete_section(const std::string& name);

    //! @brief Add a section to the binary and return the section added.
    Section& add_section(
        const Section& section,
        SECTION_TYPES type = SECTION_TYPES::UNKNOWN);

    // =============================
    // Methods to manage relocations
    // =============================

    it_relocations       relocations(void);
    it_const_relocations relocations(void) const;

    //! @brief Add a @link PE::Relocation relocation @endlink
    void add_relocation(const Relocation& relocation);

    //! @brief Remove all relocations
    void remove_all_relocations(void);

    // ===============================
    // Methods to manage DataDirectory
    // ===============================

    //! @brief Return data directories in the binary
    it_data_directories       data_directories(void);
    it_const_data_directories data_directories(void) const;

    DataDirectory&       data_directory(DATA_DIRECTORY index);
    const DataDirectory& data_directory(DATA_DIRECTORY index) const;

    Debug&       get_debug(void);
    const Debug& get_debug(void) const;

    // =======
    // Overlay
    // =======

    //! @brief Return the overlay content
    const std::vector<uint8_t>& overlay(void) const;
    std::vector<uint8_t>&       overlay(void);


    // =========================
    // Methods to manage Imports
    // =========================

    //! @brief return binary's @link PE::Import imports @endlink
    it_imports       imports(void);
    it_const_imports imports(void) const;

    //! @brief Returns the PE::Import from the given name
    //!
    //! @param[in] import_name Name of the import
    Import&          get_import(const std::string& import_name);
    const Import&    get_import(const std::string& import_name) const;

    //! @brief ``True`` if the binary import the given library name
    //!
    //! @param[in] import_name Name of the import
    bool has_import(const std::string& import_name) const;

    //! @brief Add the function @p function of the library @p library
    //!
    //! @param[in] library library name of the function
    //! @param[in] function function's name from the library to import
    ImportEntry& add_import_function(const std::string& library, const std::string& function);

    //! @brief add an imported library (i.e. `DLL`) to the binary
    Import& add_library(const std::string& name);

    //! @brief Remove the library with the given `name`
    void remove_library(const std::string& name);

    //! @brief Remove all libraries in the binary
    void remove_all_libraries(void);

    //! @brief Hook an imported function
    //!
    //! @param[in] function Function name to hook
    //! @param[in] address Address of the hook
    void hook_function(const std::string& function, uint64_t address);


    //! @brief Hook an imported function
    //!
    //! @param[in] library  Library name in which the function is located
    //! @param[in] function Function name to hook
    //! @param[in] address  Address of the hook
    void hook_function(const std::string& library, const std::string& function, uint64_t address);

    //! @brief Reconstruct the binary object and write it in  `filename`
    //!
    //! Rebuild a PE binary from the current Binary object.
    //! When rebuilding, import table and relocations are not rebuilt.
    void write(const std::string& filename);

    virtual void accept(Visitor& visitor) const override;


    // LIEF Interface
    // ==============

    //! @brief Patch the content at virtual address @p address with @p patch_value
    //!
    //! @param[in] address Address to patch
    //! @param[in] patch_value Patch to apply
    virtual void patch_address(uint64_t address, const std::vector<uint8_t>& patch_value) override;


    //! @brief Patch the address with the given value
    //!
    //! @param[in] address Address to patch
    //! @param[in] patch_value Patch to apply
    //! @param[in] size Size of the value in **bytes** (1, 2, ... 8)
    virtual void patch_address(uint64_t address, uint64_t patch_value, size_t size = sizeof(uint64_t)) override;

    //! @brief Return the content located at virtual address
    virtual std::vector<uint8_t> get_content_from_virtual_address(uint64_t virtual_address, uint64_t size) const override;

    //! @brief Return the binary's entrypoint
    virtual uint64_t entrypoint(void) const override;

    bool operator==(const Binary& rhs) const;
    bool operator!=(const Binary& rhs) const;

    virtual std::ostream& print(std::ostream& os) const override;

  private:
    Binary(void);

    //! @brief Return binary's symbols as LIEF::Symbol
    virtual LIEF::symbols_t  get_abstract_symbols(void) override;

    virtual LIEF::Header     get_abstract_header(void) const override;

    //! @brief Return binary's section as LIEF::Section
    virtual LIEF::sections_t get_abstract_sections(void) override;

    virtual std::vector<std::string> get_abstract_exported_functions(void) const override;
    virtual std::vector<std::string> get_abstract_imported_functions(void) const override;
    virtual std::vector<std::string> get_abstract_imported_libraries(void) const override;

    void update_lookup_address_table_offset(void);
    void update_iat(void);

    PE_TYPE              type_;
    DosHeader            dos_header_;
    Header               header_;
    OptionalHeader       optional_header_;

    bool                 has_tls_;
    bool                 has_imports_;
    bool                 has_signature_;
    bool                 has_exports_;
    bool                 has_resources_;
    bool                 has_exceptions_;
    bool                 has_relocations_;
    bool                 has_debug_;
    bool                 has_configuration_;

    Signature            signature_;
    TLS                  tls_;
    sections_t           sections_;
    data_directories_t   data_directories_;
    symbols_t            symbols_;
    strings_table_t      strings_table_;
    relocations_t        relocations_;
    ResourceNode*        resources_;
    imports_t            imports_;
    Export               export_;
    Debug                debug_;
    std::vector<uint8_t> overlay_;

    std::map<std::string, std::map<std::string, uint64_t>> hooks_;
};

}
}
#endif
