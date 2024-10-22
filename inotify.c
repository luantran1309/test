#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <pwd.h>
#include <sys/stat.h>

#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

// Hàm lấy thời gian hiện tại
void get_current_time(char *buffer, size_t size) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Hàm lấy tên người dùng
void get_username(char *buffer, size_t size) {
    struct passwd *pw = getpwuid(geteuid());
    if (pw) {
        strncpy(buffer, pw->pw_name, size);
        buffer[size - 1] = '\0';
    } else {
        strncpy(buffer, "unknown", size);
    }
}

// Hàm lấy địa chỉ IP
void get_ip_address(char *buffer, size_t size) {
    FILE *fp = popen("hostname -I", "r");
    if (fp == NULL) {
        strncpy(buffer, "unknown", size);
    } else {
        fgets(buffer, size, fp);
        buffer[strcspn(buffer, "\n")] = '\0'; // Xóa ký tự newline
        pclose(fp);
    }
}

// Hàm tạo thư mục log nếu chưa tồn tại
void create_log_directory(const char *dir_path) {
    struct stat st;
    // Kiểm tra xem thư mục đã tồn tại chưa
    if (stat(dir_path, &st) != 0) {
        // Nếu không tồn tại, tạo thư mục
        if (mkdir(dir_path, 0755) == -1) {
            perror("Error creating log directory");
            exit(EXIT_FAILURE);
        }
    }
}

// Hàm ghi log
void log_event(const char *watch_directory, const char *event_desc, const char *filename) {
    const char *log_file_path = "/var/log/logfile/activity.log"; // Đường dẫn tệp log
    FILE *log_file = fopen(log_file_path, "a");
    if (log_file == NULL) {
        perror("fopen");
        return;
    }

    char time_str[64];
    char user[64];
    char ip[64];

    get_current_time(time_str, sizeof(time_str));
    get_username(user, sizeof(user));
    get_ip_address(ip, sizeof(ip));

    // Ghi log theo định dạng mong muốn
    fprintf(log_file, "[%s] User: %s, IP: %s, Watch Directory: %s, Event: %s, File: %s\n",
            time_str, user, ip, watch_directory, event_desc, filename);
    fclose(log_file);
}

// Cập nhật hàm xử lý sự kiện để truyền thông tin thư mục giám sát
void handle_event(const char *watch_directory, struct inotify_event *event) {
    if (event->len == 0) return;

    if (event->mask & IN_CREATE) {
        log_event(watch_directory, "File created", event->name);
    }
    if (event->mask & IN_DELETE) {
        log_event(watch_directory, "File deleted", event->name);
    }
    if (event->mask & IN_MODIFY) {
        log_event(watch_directory, "File modified", event->name);
    }
    if (event->mask & IN_MOVED_FROM) {
        log_event(watch_directory, "File moved from", event->name);
    }
    if (event->mask & IN_MOVED_TO) {
        log_event(watch_directory, "File moved to", event->name);
    }
}

// Cập nhật hàm main để truyền đường dẫn giám sát
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_watch>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *log_dir = "/var/log/logfile"; // Đường dẫn thư mục log
    create_log_directory(log_dir); // Tạo thư mục log nếu chưa tồn tại

    int inotify_fd = inotify_init();
    if (inotify_fd == -1) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    int wd = inotify_add_watch(inotify_fd, argv[1], IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO);
    if (wd == -1) {
        perror("inotify_add_watch");
        close(inotify_fd);
        exit(EXIT_FAILURE);
    }

    printf("Monitoring %s for changes... Press Ctrl+C to stop.\n", argv[1]);

    char buf[BUF_LEN] __attribute__((aligned(8)));
    ssize_t num_read;

    while (1) {
        num_read = read(inotify_fd, buf, BUF_LEN);
        if (num_read == 0) {
            fprintf(stderr, "Read from inotify fd returned 0!\n");
            break;
        }

        if (num_read == -1) {
            perror("read");
            break;
        }

        for (char *ptr = buf; ptr < buf + num_read; ) {
            struct inotify_event *event = (struct inotify_event *) ptr;
            handle_event(argv[1], event); // Truyền thêm thông tin thư mục giám sát
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    if (inotify_rm_watch(inotify_fd, wd) == -1) {
        perror("inotify_rm_watch");
    }
    close(inotify_fd);
    printf("Stopped monitoring.\n");
    exit(EXIT_SUCCESS);
}
