import { Card, CardContent } from "@/components/ui/card"
import type { IProperty } from "@/types/property.interface"
interface Props {
    property: IProperty
}
export default function PropertyPriceCard({ property }: Props) {

    return (

        <Card>

            <CardContent className="p-6">

                <div className="flex justify-between">

                    <div>
                        <p className="text-muted-foreground">Цена</p>
                        <p className="text-2xl font-semibold">
                            {property.price.toLocaleString()} ₽
                        </p>
                    </div>

                    <div>
                        <p className="text-muted-foreground">Тип сделки</p>
                        <p>{property.dealType}</p>
                    </div>

                </div>

            </CardContent>

        </Card>

    )
}