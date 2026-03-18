import { Card, CardContent } from "@/components/ui/card"
import type { IProperty } from "@/types/property.interface"
interface Props {
    property: IProperty
}

export default function PropertyCharacteristics({ property }: Props) {
    return (
        <Card>
            <CardContent className="p-6 space-y-4">

                <h2 className="text-lg font-semibold">
                    Характеристики
                </h2>

                <div className="grid grid-cols-3 gap-4">

                    <div>
                        <p className="text-muted-foreground text-sm">Площадь</p>
                        <p>{property.area} м²</p>
                    </div>

                    <div>
                        <p className="text-muted-foreground text-sm">Комнаты</p>
                        <p>{property.rooms}</p>
                    </div>

                    <div>
                        <p className="text-muted-foreground text-sm">Этаж</p>
                        <p>{property.floor}/{property.totalFloors}</p>
                    </div>

                    <div>
                        <p className="text-muted-foreground text-sm">Год постройки</p>
                        <p>{property.yearBuilt}</p>
                    </div>

                    <div>
                        <p className="text-muted-foreground text-sm">Тип недвижимости</p>
                        <p>{property.propertyType}</p>
                    </div>

                    <div>
                        <p className="text-muted-foreground text-sm">Район</p>
                        <p>{property.district}</p>
                    </div>

                </div>

            </CardContent>
        </Card>
    )
}