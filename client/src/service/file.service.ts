import { axiosWithAuth } from "@/api/api.interceptors"

export const FileService = {
    async uploadFile(file: File, companyId: number) {
        const formData = new FormData()
        formData.append('file', file)
        const { data } = await axiosWithAuth.post(`company/${companyId}/import-from-csv`, formData, { headers: { 'Content-Type': 'multipart/form-data' } })
        return data
    }
}