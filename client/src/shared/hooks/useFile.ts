import { FileService } from "@/service/file.service";
import { useMutation } from "@tanstack/react-query";
import { toast } from "react-toastify";

export function useUploadFile(companyId: number) {
    return useMutation({
        mutationKey: ['file'],
        mutationFn: (file: File) => FileService.uploadFile(file, companyId),
        onSuccess: () => {
            toast.success('Файл успешно загружен')
        },
        onError: (error: Error) => {
            toast.error(error.message || 'Ошибка при загрузке файла')
        },
    })
}