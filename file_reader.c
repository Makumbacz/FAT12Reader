#include "file_reader.h"
#include "tested_declarations.h"
#include "rdebug.h"
#include "tested_declarations.h"
#include "rdebug.h"

struct disk_t* disk_open_from_file(const char* volume_file_name){

    if(volume_file_name == NULL){
        errno = EFAULT;
        return NULL;
    }
    struct disk_t *disk = (struct disk_t*) malloc(sizeof(struct disk_t));
    if(disk == NULL){
        errno = ENOMEM;
        return NULL;
    }
    disk->disk_file = fopen(volume_file_name,"rb");
    if(disk->disk_file == NULL){
        errno = ENOENT;
        free(disk);
        return NULL;
    }
    disk->sectors_per_volume = get_volume_size(disk);

    return disk;
}

int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read){
    if(buffer == NULL || pdisk == NULL || first_sector < 0 || sectors_to_read <= 0){
        errno = EFAULT;
        return -1;
    }
    if(pdisk->sectors_per_volume - first_sector < (uint32_t )sectors_to_read){
        errno = ERANGE;
        return -1;
    }
    fseek(pdisk->disk_file, first_sector * BYTES_PER_SECTOR, SEEK_SET);
    int b = fread(buffer,BYTES_PER_SECTOR,sectors_to_read,pdisk->disk_file);
    return b;
}
int disk_close(struct disk_t* pdisk){
    if(pdisk == NULL){
        errno = EFAULT;
        return -1;
    }
    fclose(pdisk->disk_file);
    free(pdisk);
    return 0;
}

lba_t get_volume_size(struct disk_t *disk) {
    fseek(disk->disk_file, 0, SEEK_END);
    int pos = ftell(disk->disk_file);
    return pos / BYTES_PER_SECTOR;
}

void set_geometry(struct volume_t *volume){
    volume->volume_start = 0;
    volume->fat1_position = volume->volume_start + volume->super->reserved_sectors;
    volume->fat2_position = volume->volume_start + volume->super->reserved_sectors + volume->super->sectors_per_fat;
    volume->rootdir_position = volume->volume_start + volume->super->reserved_sectors + volume->super->fat_count * volume->super->sectors_per_fat;
    volume->sectors_per_rootdir = (volume->super->root_dir_capacity * sizeof(struct fat_small_file_t)) / volume->super->bytes_per_sector;
    if((volume->super->root_dir_capacity  * sizeof(struct fat_small_file_t)% volume->super->bytes_per_sector != 0))
        volume->sectors_per_rootdir++;
    volume->cluster2_position = volume->rootdir_position + volume->sectors_per_rootdir;
    volume->volume_size = volume->super->logical_sectors16 == 0 ? volume->super->logical_sectors32 :volume->super->logical_sectors16;
    volume->user_size = volume->volume_size - (volume->super->fat_count * volume->super->sectors_per_fat) - volume->super->reserved_sectors - volume->sectors_per_rootdir ;
    volume->number_of_cluster_per_volume = volume->user_size / volume->super->sectors_per_cluster;
}

int read_fat(struct volume_t* volume, struct disk_t* disk){
    volume->fat = (uint8_t*) malloc(volume->super->bytes_per_sector * volume->super->sectors_per_fat);
    uint8_t *fat_2 = (uint8_t*) malloc(volume->super->bytes_per_sector * volume->super->sectors_per_fat);
    if(volume->fat == NULL || fat_2 == NULL){
        free(fat_2);
        free(volume->fat);
        errno = ENOMEM;
        return 1;
    }

    disk_read(disk, (int32_t)volume->fat1_position,volume->fat, volume->super->sectors_per_fat);
    disk_read(disk, (int32_t)volume->fat2_position,fat_2, volume->super->sectors_per_fat);
    if(memcmp(fat_2, volume->fat, volume->super->bytes_per_sector * volume->super->sectors_per_fat) != 0){
        free(fat_2);
        free(volume->fat);
        errno = EINVAL;
        return 2;
    }
    free(fat_2);
    return 0;
}

int read_root_dir(struct volume_t* volume, struct disk_t* disk){
    volume->root_dir = (struct fat_small_file_t*)malloc(volume->sectors_per_rootdir * volume->super->bytes_per_sector);
    if(volume->root_dir == NULL){
        errno = ENOMEM;
        return 1;
    }
    disk_read(disk,(int32_t)volume->rootdir_position,volume->root_dir,(int32_t)volume->sectors_per_rootdir);
    return 0;
}

int read_fat_content(struct volume_t* volume){
    volume->fat_content = (uint16_t*) calloc((volume->number_of_cluster_per_volume + 3), sizeof(uint16_t));
    if(volume->fat_content == NULL){
        errno = ENOMEM;
        return 1;
    }

    for (lba_t i = 0, j = 0; i < volume->number_of_cluster_per_volume + 2; i += 2, j += 3) {
        uint8_t b1 = volume->fat[j];
        uint8_t b2 = volume->fat[j + 1];
        uint8_t b3 = volume->fat[j + 2];

        uint16_t c1 = ((b2 & 0x0F) << 8) | b1;
        uint16_t c2 = ((b2 & 0xF0) >> 4) | (b3 << 4);

        volume->fat_content[i] = c1;
        volume->fat_content[i + 1] = c2;
    }


    return 0;
}

struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector){
    if(pdisk == NULL){
        errno = EFAULT;
        return NULL;
    }
    struct volume_t* volume = (struct volume_t*) malloc(sizeof(struct volume_t));
    if(volume == NULL){
        errno = ENOMEM;
        return NULL;
    }
    volume->super = (struct fat_super_t*) malloc(sizeof(struct fat_super_t));
    if(volume->super == NULL){
        free(volume);
        errno = ENOMEM;
        return NULL;
    }

    if(disk_read(pdisk,(int32_t)first_sector,volume->super,1) == -1) {
        free(volume->super);
        free(volume);
        return NULL;
    }

    if ((volume->super->fat_count > 2 || volume->super->fat_count < 1)  ||
        (!volume->super->logical_sectors16 && !volume->super->logical_sectors32)||
        volume->super->reserved_sectors <= 0 ||
        (volume->super->sectors_per_cluster < 1 || volume->super->sectors_per_cluster > 128)){
        fat_close(volume);
        errno = EINVAL;
        return NULL;
    }
    volume->disk = pdisk;
    set_geometry(volume);
    int err = read_fat(volume,pdisk);
    if(err) {
        fat_close(volume);
        return NULL;
    }
    err = read_root_dir(volume,pdisk);
    if(err){
        fat_close(volume);
        return NULL;
    }
    err = read_fat_content(volume);
    if(err){
        fat_close(volume);
        return NULL;
    }

    return volume;
}
int fat_close(struct volume_t* pvolume){
    if(pvolume == NULL){
        return 1;
    }
    free(pvolume->root_dir);
    free(pvolume->fat_content);
    free(pvolume->fat);
    free(pvolume->super);
    free(pvolume);
    return 0;
}
struct fat_small_file_t* find_filename(struct volume_t* volume, const char* filename){

    for (int i = 0; i < volume->super->root_dir_capacity ; ++i) {
        if(volume->root_dir[i].name[0] == 0)
            break;
        if(volume->root_dir[i].name[0] == FAT_DELETED_MAGIC)
            continue;
        char* buffer = malloc(13);
        if(buffer == NULL)
            return NULL;
        int j = 0;
        for (; j < 8 ; ++j) {
            if(volume->root_dir[i].name[j] == ' ')
                break;
            buffer[j] = volume->root_dir[i].name[j];
        }
        if(volume->root_dir[i].name[8]!= ' '){
            buffer[j] = '.';
            j++;
            for (int k = 8; k < 11; ++j, ++k) {
                if(volume->root_dir[i].name[k] == ' ')
                    break;
                buffer[j] = volume->root_dir[i].name[k];
            }
        }
        buffer[j] = '\0';
        if(strcmp(buffer,filename) == 0) {
            free(buffer);
            return &volume->root_dir[i];
        }
        free(buffer);
    }
    return 0;
}

uint32_t get_number_of_clusters_from_file(cluster_t first_cluster, struct volume_t* volume){
    uint32_t counter = 0;
    for(;; counter++){
        if(first_cluster >= 0xFF8)
            break;
        first_cluster = get_next_cluster(first_cluster,volume);
    }
    return counter;
}

cluster_t get_next_cluster(cluster_t current_cluster, struct volume_t *volume){
    return volume->fat_content[current_cluster];

}
struct file_t* file_open(struct volume_t* pvolume, const char* file_name){
    if(pvolume == NULL || file_name == NULL){
        errno = EFAULT;
        return NULL;
    }
    struct fat_small_file_t* file_found = find_filename(pvolume,file_name);
    if(file_found == NULL){
        errno = ENOENT;
        return NULL;
    }
    if((file_found->attributes & FAT_ATRIB_DIRECTORY) != 0){
        errno = EISDIR;
        return NULL;
    }
    uint32_t cluster_index =  ((uint32_t)file_found->high_chain_index << 16) | (uint32_t)file_found->low_chain_index;
    struct file_t* file = (struct file_t*) malloc(sizeof(struct file_t));
    if(file == NULL){
        errno = ENOMEM;
        return NULL;
    }
    uint32_t counter = get_number_of_clusters_from_file(cluster_index,pvolume);
    file->content = (uint8_t*) malloc(counter * pvolume->super->sectors_per_cluster * pvolume->super->bytes_per_sector + 1);
    if(file->content == NULL) {
        free(file);
        errno = ENOMEM;
        return NULL;
    }
    file->size = file_found->size;
    file->content_offset = 0;
    file->position = 0;
    for(;cluster_index <= 0xFF8;){

        lba_t cluster_position = pvolume->cluster2_position + (cluster_index - 2) * pvolume->super->sectors_per_cluster;
        disk_read(pvolume->disk,(int32_t)cluster_position,file->content + file->content_offset, pvolume->super->sectors_per_cluster);

        cluster_index = get_next_cluster(cluster_index,pvolume);
        file->content_offset += pvolume->super->sectors_per_cluster * pvolume->super->bytes_per_sector;
    }
    file->content[file->size] = '\0';

    return file;
}
int file_close(struct file_t* stream){
    if(stream == NULL){
        errno = EFAULT;
        return -1;
    }
    free(stream->content);
    free(stream);
    return 0;
}
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream){
    if(ptr == NULL || stream == NULL){
        errno = EFAULT;
        return -1;
    }
    size_t element_read = 0;
    for (uint32_t i = 0; i < nmemb; ++i,++element_read) {
        for (uint32_t j = 0; j < size; ++j,++stream->position) {
            if (stream->position == stream->size)
                return element_read;
            *((uint8_t *) ptr + i + j) = *(stream->content + stream->position);
        }
    }

    return element_read;
}
int32_t file_seek(struct file_t* stream, int32_t offset, int whence){
    if(stream == NULL){
        errno = EFAULT;
        return -1;
    }
    if(whence < 0 || whence > 2){
        errno = EINVAL;
        return -1;
    }

    if(whence == SEEK_SET){
        if((int32_t)stream->size < offset){
            errno = ENXIO;
            return -1;
        }
        stream->position = offset;
    }else if(whence == SEEK_CUR){
        if((int32_t)stream->size < offset + (int32_t)stream->position){
            errno = ENXIO;
            return -1;
        }
        stream->position = offset + stream->position;
    }else{
        if((int32_t)stream->size < -offset){
            errno = ENXIO;
            return -1;
        }
        stream->position = stream->size + offset;
    }
    return (int32_t)stream->position;
}

int set_proper_name(struct fat_small_file_t fat_file,struct dir_entry_t* entry){
    int j = 0;
    for (; j < 8 ; ++j) {
        if(fat_file.name[j] == ' ')
            break;
        entry->name[j] = fat_file.name[j];
    }
    if(fat_file.name[8]!= ' '){
        entry->name[j]= '.';
        j++;
        for (int k = 8; k < 11; ++j, ++k) {
            if(fat_file.name[k] == ' ')
                break;
            entry->name[j] = fat_file.name[k];
        }
    }
    entry->name[j] = '\0';
    return 0;
}

int set_attribute(struct fat_small_file_t fat_file,struct dir_entry_t* entry){
    if(fat_file.attributes & FAT_ATRIB_READONLY)
        entry->is_readonly = 1;
    if(fat_file.attributes & FAT_ATRIB_SYSTEM)
        entry->is_system = 1;
    if(fat_file.attributes & FAT_ATRIB_HIDDEN)
        entry->is_hidden = 1;
    if(fat_file.attributes & FAT_ATRIB_DIRECTORY)
        entry->is_directory = 1;
    if(fat_file.attributes & FAT_ATRIB_ARCHIVE)
        entry->is_archived = 1;


    return 0;
}

struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path){
    if(pvolume == NULL){
        errno = EFAULT;
        return NULL;
    }

    struct dir_t* dir = calloc(1, sizeof(struct dir_t));
    if(dir == NULL){
        errno = ENOMEM;
        return NULL;
    }
    dir->entry = calloc(pvolume->super->root_dir_capacity, sizeof(struct dir_entry_t));

    if(dir->entry == NULL){
        free(dir);
        errno = ENOMEM;
        return NULL;
    }

    if(strcmp(dir_path,"\\") != 0){
        dir_close(dir);
        errno = ENOENT;
        return NULL;
    }
    for (int i = 0; i < pvolume->super->root_dir_capacity; ++i) {
        if(pvolume->root_dir[i].name[0] == 0)
            break;
        if(pvolume->root_dir[i].name[0] == FAT_DELETED_MAGIC ||
           (pvolume->root_dir[i].attributes & FAT_ATRIB_VOLUME) != 0)
            continue;
        set_proper_name(pvolume->root_dir[i],&dir->entry[dir->size]);
        dir->entry[dir->size].size = pvolume->root_dir[i].size;
        set_attribute(pvolume->root_dir[i],&dir->entry[dir->size]);
        dir->size++;
    }

    return dir;
}
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry){
    if(pdir == NULL || pentry == NULL){
        errno = EFAULT;
        return -1;
    }
    if(pdir->size == pdir->entry_index)
        return 1;
    memcpy(pentry, &pdir->entry[pdir->entry_index], sizeof(struct dir_entry_t));
    pdir->entry_index++;

    return 0;
}
int dir_close(struct dir_t* pdir){
    if(pdir == NULL){
        errno = EFAULT;
        return -1;
    }
    free(pdir->entry);
    free(pdir);
    return 0;
}


