set(greenfs 
greenfs_main.cc
greenfs_init.cc
)
add_executable(greenfs ${greenfs})
target_link_libraries(greenfs osd os global 
  ${BLKID_LIBRARIES} ${CMAKE_DL_LIBS} ${AIO_LIBRARIES})