// Open a file through io_uring only: no open/openat system call is made.
#include <liburing.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct io_uring ring; struct io_uring_sqe *sqe; struct io_uring_cqe *cqe;
    if (io_uring_queue_init(4, &ring, 0) < 0) { perror("init"); return 1; }
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_openat(sqe, AT_FDCWD, argv[1], O_RDONLY, 0);
    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    printf("io_uring open result: %d\n", cqe->res);
    return cqe->res < 0;
}
