# -*- coding: utf-8 -*-

# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

import scrapy
from scrapy.item import Item, Field

class NndItem(Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    link = Field()
    attack_method = Field()
    vuln_name = Field()
    cnnvd_id = Field()
    release_date = Field()
    update_date = Field()
    severity = Field()
    vuln_type = Field()
    cve_id = Field()