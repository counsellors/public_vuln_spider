# -*- coding: utf-8 -*-

# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

from scrapy.item import Item, Field


class AospItem(Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    cve_id = Field()
    m_references = Field()
    severity = Field()
    devices = Field()
    versions = Field()
    report_date = Field()
    create_time = Field()
    update_time = Field()
    file_path = Field()
    bulletins_date = Field()