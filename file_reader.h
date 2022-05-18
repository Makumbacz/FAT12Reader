//
// Created by arasi on 11.12.2021.
//

#ifndef P2FAT_FILE_READER_H
#define P2FAT_FILE_READER_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <bits/types/FILE.h>

#define BYTES_PER_SECTOR 512
#define FAT_DELETED_MAGIC ((char)0xE5)
typedef uint16_t fat_date_t;
typedef uint16_t fat_time_t;
typedef uint32_t lba_t; //liczba sektorowa, polozenie sektorow
typedef uint32_t cluster_t; // liczba klastrow, polozenie klastrow


enum fat_attributes_t{
    FAT_ATRIB_READONLY = 0x01,
    FAT_ATRIB_HIDDEN = 0x02,
    FAT_ATRIB_SYSTEM = 0x04,
    FAT_ATRIB_VOLUME = 0x08,
    FAT_ATRIB_DIRECTORY = 0x10,
    FAT_ATRIB_ARCHIVE = 0x20,
 //   FAT_ATRIB_LFN = 0x0F,
}__attribute__(( packed ));

struct fat_super_t {
    uint8_t jump_code[3];
    char oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t fat_count;
    uint16_t root_dir_capacity;
    uint16_t logical_sectors16;
    uint8_t media_type;
    uint16_t sectors_per_fat;
    uint16_t chs_sectors_per_track;
    uint16_t chs_tracks_per_cylinder;
    uint32_t hidden_sectors;
    uint32_t logical_sectors32;
    uint8_t media_id;
    uint8_t chs_head;
    uint8_t ext_bpb_signature;
    uint32_t serial_number;
    char volume_label[11];
    char fsid[8];
    uint8_t boot_code[448];
    uint16_t magic;
} __attribute__ (( packed ));

struct fat_small_file_t{
    char name[8 + 3];
    enum fat_attributes_t attributes;
    uint8_t __reserved0;
    uint8_t cration_time_ms;
    fat_time_t creation_time;
    fat_date_t creation_date;
    fat_time_t last_access_time;
    uint16_t high_chain_index;
    fat_time_t last_modification_time;
    fat_date_t last_modification_date;
    uint16_t low_chain_index;
    uint32_t size;
} __attribute__ ((packed));

struct disk_t{
    FILE* disk_file;
    lba_t sectors_per_volume;

};
struct dir_entry_t{
    char name[8+3+2];
    uint32_t size;
    uint8_t is_archived;
    uint8_t is_readonly;
    uint8_t is_system;
    uint8_t is_hidden;
    uint8_t is_directory;
    uint32_t foo[2];
    uint16_t foo2;

} __attribute__(( packed ));

struct volume_t{
    struct fat_super_t* super;
    struct fat_small_file_t* root_dir;
    struct disk_t *disk;
    uint8_t *fat;
    uint16_t *fat_content;
    lba_t volume_start;
    lba_t fat1_position;
    lba_t fat2_position;
    lba_t rootdir_position;
    lba_t sectors_per_rootdir;
    lba_t cluster2_position;
    lba_t volume_size;
    lba_t user_size;
    lba_t number_of_cluster_per_volume;

};
struct dir_t{
    struct dir_entry_t *entry;
    uint32_t size;
    uint32_t entry_index;
};
struct file_t{
    uint8_t* content;
    uint32_t position;
    cluster_t content_offset;
    uint32_t size;
};

struct disk_t* disk_open_from_file(const char* volume_file_name);
int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read);
int disk_close(struct disk_t* pdisk);
struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector);
int fat_close(struct volume_t* pvolume);
struct file_t* file_open(struct volume_t* pvolume, const char* file_name);
int file_close(struct file_t* stream);
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream);
int32_t file_seek(struct file_t* stream, int32_t offset, int whence);
struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path);
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry);
int dir_close(struct dir_t* pdir);
lba_t get_volume_size(struct disk_t *disk);
cluster_t get_next_cluster(cluster_t current_cluster, struct volume_t *volume);
#endif //P2FAT_FILE_READER_H
