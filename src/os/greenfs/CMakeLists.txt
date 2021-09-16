set(greenfs 
greenfs_main.cc
)
add_executable(greenfs ${greenfs})
target_link_libraries(greenfs global osd os global-static common
  ${BLKID_LIBRARIES} ${CMAKE_DL_LIBS} ${AIO_LIBRARIES} ${RDMA_LIBRARIES})