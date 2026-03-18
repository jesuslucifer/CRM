import { NavLink } from "react-router"

import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { ICreateProperty, IProperty } from "@/types/property.interface"
import EditPropertyDialog from "@/shared/forms/EditPropertyDialog"
interface Props {
    property: IProperty
}
export default function PropertyCard({ property }: Props) {

    return (

        <Card className="hover:shadow-md transition">

            <CardContent className="p-5 space-y-4">

                <div className="flex justify-between items-start">

                    <h3 className="font-semibold text-lg">
                        {property.title}
                    </h3>

                    <Badge>
                        {property.propertyStatus}
                    </Badge>

                </div>

                <p className="text-sm text-muted-foreground">
                    {property.city}, {property.address}
                </p>

                <div className="grid grid-cols-3 text-sm gap-2">

                    <div>
                        <p className="text-muted-foreground">Площадь</p>
                        <p>{property.area} м²</p>
                    </div>

                    <div>
                        <p className="text-muted-foreground">Комнаты</p>
                        <p>{property.rooms}</p>
                    </div>

                    <div>
                        <p className="text-muted-foreground">Этаж</p>
                        <p>{property.floor}/{property.totalFloors}</p>
                    </div>

                </div>

                <div className="text-lg font-semibold">
                    {property.price.toLocaleString()} ₽
                </div>

                <div className="flex gap-2 pt-2">

                    <Button asChild size="sm">
                        <NavLink to={`${property.id}`}>
                            Открыть
                        </NavLink>
                    </Button>


                    <EditPropertyDialog property={property} id={property.id} />



                    <Button size="sm" variant="destructive">
                        Удалить
                    </Button>

                </div>

            </CardContent>

        </Card>

    )
}