

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import PropertyCard from "@/features/property/PropertyCard"
import PropertyStats from "@/features/property/PropertyStats"
import CreatePropertyDialog from "@/shared/forms/CreatePropertyDilog"
import { useCurrentCompany } from "@/shared/hooks/useCompany"
import { useUploadFile } from "@/shared/hooks/useFile"
import { useGetAllProperty } from "@/shared/hooks/useProperty"
import { Upload, type IUpload, type IUploadFile } from "@/shared/widgets/uploadFile"

export function PropertyPage() {

    const { data: company } = useCurrentCompany()
    const { data: properties, isLoading } = useGetAllProperty(company?.id!)
    const { mutate: uploadFile } = useUploadFile(company?.id!)
    const handleUploadFile = (event: any) => {
        const file: File = event.target.files[0];
        uploadFile(file)
        console.log(`Файл: ${file.name}, Размер: ${file.size}Б, Тип: ${file.type}`);

    }
    if (isLoading) return <div>Loading properties...</div>

    return (
        <div className="space-y-6">

            <div className="flex items-center justify-between">

                <div>
                    <h1 className="text-2xl font-bold">
                        Объекты недвижимости
                    </h1>

                    <p className="text-sm text-muted-foreground">
                        Управляйте объектами вашей компании
                    </p>

                </div>

                <CreatePropertyDialog />
                {/* <Upload /> */}
                <label >
                    <input type="file" accept=".csv" onChange={(e) => handleUploadFile(e)} />
                </label>
                {/* <Button>
                    Выгрузить из csv
                </Button> */}
            </div>

            <PropertyStats properties={properties} />

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">

                {properties?.map(property => (
                    <PropertyCard key={property.id} property={property} />
                ))}

            </div>

        </div>
    )
}