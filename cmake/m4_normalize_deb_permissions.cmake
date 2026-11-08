# CPack executes this after staging and before building the DEB payload.
# Package modes must not inherit developer/runner umask or setgid directory bits.
if(NOT DEFINED CPACK_TEMPORARY_DIRECTORY)
    message(FATAL_ERROR "CPACK_TEMPORARY_DIRECTORY missing during M4 package staging")
endif()
set(_root "${CPACK_TEMPORARY_DIRECTORY}/usr")
if(NOT IS_DIRECTORY "${_root}")
    message(FATAL_ERROR "DEB staging directory not found: ${_root}")
endif()
file(GLOB_RECURSE _entries LIST_DIRECTORIES TRUE "${_root}/*")
list(APPEND _entries "${_root}")
foreach(_entry IN LISTS _entries)
    if(IS_DIRECTORY "${_entry}" AND NOT IS_SYMLINK "${_entry}")
        file(CHMOD "${_entry}" PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE)
    endif()
endforeach()
message(STATUS "M4: normalized staged /usr directory permissions to 0755")
