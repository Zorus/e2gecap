include(FindPkgConfig)
pkg_check_modules(PC_ECAP QUIET "libecap")

if(PC_ECAP_FOUND)
    # Set version
    set(ECAP_CXX_FLAGS "")
    if(NOT LIBECAP_VERSION VERSION_LESS "1.0.0")
        set(ECAP_CXX_FLAGS "-DV100")
    endif()
    set(ECAP_CXX_FLAGS "${ECAP_CXX_FLAGS} -DLIBECAP_VERSION=\\\"${PC_ECAP_VERSION}\\\"")

    # Find includes
    find_path(
        ECAP_INCLUDE_DIRS
        NAMES
        libecap
        HINTS
        ${PC_ECAP_INCLUDE_DIRS}
    )

    # Find libs
    find_library(
        ECAP_LIBRARIES
        NAMES libecap.so libecap.so.3 libecape.so.3.0.0
        HINTS ${PC_ECAP_LIBRARY_DIRS}
    )
endif()



include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ECAP DEFAULT_MSG ECAP_LIBRARIES ECAP_INCLUDE_DIRS ECAP_CXX_FLAGS)
mark_as_advanced(ECAP_LIBRARIES ECAP_INCLUDE_DIRS ECAP_CXX_FLAGS)