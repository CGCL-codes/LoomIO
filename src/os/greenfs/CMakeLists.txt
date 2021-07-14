set(greenfs greenfs_main.cc)
add_executable(greenfs ${greenfs})
target_link_libraries(greenfs global
  ${BLKID_LIBRARIES} ${CMAKE_DL_LIBS})