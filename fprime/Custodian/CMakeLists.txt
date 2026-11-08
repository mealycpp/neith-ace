set(C "${CMAKE_CURRENT_LIST_DIR}/crypto")
include_directories("${CMAKE_CURRENT_LIST_DIR}" "${C}/ascon" "${C}/xmss" "${C}/native/shim")
set(SOURCE_FILES
  "${CMAKE_CURRENT_LIST_DIR}/Custodian.fpp"
  "${CMAKE_CURRENT_LIST_DIR}/Custodian.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/neith_shim.c"
  "${C}/ascon/hash.c"
  "${C}/native/xmss_wrap.c" "${C}/native/sha_shim.c"
  "${C}/xmss/params.c" "${C}/xmss/hash.c" "${C}/xmss/fips202.c" "${C}/xmss/hash_address.c"
  "${C}/xmss/randombytes.c" "${C}/xmss/wots.c" "${C}/xmss/xmss.c" "${C}/xmss/xmss_core_fast.c"
  "${C}/xmss/xmss_commons.c" "${C}/xmss/utils.c")
register_fprime_module()
