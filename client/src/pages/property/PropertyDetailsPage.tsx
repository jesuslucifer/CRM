import { useParams } from "react-router"



import { Button } from "@/components/ui/button"
import { useGetPropertyById } from "@/shared/hooks/useProperty"
import PropertyHeader from "@/features/property/PropertyHeader"
import PropertyPriceCard from "@/features/property/PropertyPriceCard"
import EditPropertyDialog from "@/shared/forms/EditPropertyDialog"
import PropertyCharacteristics from "@/features/property/PropertyCharacteristics"
import PropertyDescription from "@/features/property/PropertyDescription"
import PropertyFutureFeatures from "@/features/property/PropertyFutureFeatures"

export function PropertyDetailsPage() {

    const { propertyId } = useParams()

    const { data: property, isLoading } = useGetPropertyById(Number(propertyId))

    if (isLoading) return <div>Loading property...</div>
    if (!property) return <div>Property not found</div>

    return (

        <div className="space-y-6">

            <PropertyHeader property={property} />

            <PropertyPriceCard property={property} />

            <PropertyCharacteristics property={property} />

            <PropertyDescription property={property} />

            <PropertyFutureFeatures />

            <div className="flex gap-3">

                <EditPropertyDialog
                    property={property}
                    id={property.id}
                />

                <Button variant="destructive">
                    Удалить
                </Button>

            </div>

        </div>

    )
}