using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Api.Gateway.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitCore : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "gateway_endpoints",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    method = table.Column<string>(type: "text", nullable: false),
                    path = table.Column<string>(type: "text", nullable: false),
                    scope = table.Column<string>(type: "text", nullable: false),
                    display_name = table.Column<string>(type: "text", nullable: false),
                    normalized_name = table.Column<string>(type: "text", nullable: false),
                    description = table.Column<string>(type: "text", nullable: true),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_gateway_endpoints", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "gateway_role_permissions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    role = table.Column<string>(type: "text", nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    is_allowed = table.Column<bool>(type: "boolean", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_gateway_role_permissions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_gateway_role_permissions_gateway_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "gateway_endpoints",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_gateway_endpoints_normalized_name",
                table: "gateway_endpoints",
                column: "normalized_name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_gateway_role_permissions_endpoint_id",
                table: "gateway_role_permissions",
                column: "endpoint_id");

            migrationBuilder.CreateIndex(
                name: "IX_gateway_role_permissions_role_endpoint_id",
                table: "gateway_role_permissions",
                columns: new[] { "role", "endpoint_id" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "gateway_role_permissions");

            migrationBuilder.DropTable(
                name: "gateway_endpoints");
        }
    }
}
